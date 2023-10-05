#include <bit>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/ethdb/file/local_database.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>
#include <silkworm/silkrpc/test/context_test_base.hpp>

namespace silkworm::rpc::test {

std::filesystem::path get_tests_dir() {
    auto working_dir = std::filesystem::current_path();

    while (!std::filesystem::exists(working_dir / "third_party" / "execution-apis") && working_dir != "/") {
        working_dir = working_dir.parent_path();
    }

    return working_dir / "third_party" / "execution-apis" / "tests";
}

std::shared_ptr<mdbx::env_managed> open_db(const std::string& chaindata_dir) {
    db::EnvConfig chain_conf{
        .path = chaindata_dir,
        .create = true,
        .exclusive = true,
        .in_memory = true,
        .shared = false};

    return std::make_shared<mdbx::env_managed>(db::open_env(chain_conf));
}

std::unique_ptr<InMemoryState> populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir) {
    auto genesis_json_path = tests_dir / "genesis.json";
    std::ifstream genesis_json_input_file(genesis_json_path);
    nlohmann::json genesis_json;
    genesis_json_input_file >> genesis_json;
    auto state_buffer = std::make_unique<InMemoryState>();

    // Allocate accounts
    if (genesis_json.contains("alloc")) {
        auto state_table_storage = txn.rw_cursor_dup_sort(db::table::kPlainState);

        for (const auto& item : genesis_json["alloc"].items()) {
            const auto& account_alloc_json = item.value();

            evmc::address account_address = hex_to_address(item.key());
            const auto acc_balance{intx::from_string<intx::uint256>(account_alloc_json.at("balance"))};

            intx::uint256 acc_nonce{0};
            if (account_alloc_json.contains("nonce")) {
                acc_nonce = intx::from_string<intx::uint256>(account_alloc_json.at("nonce"));
            }

            Account account{acc_nonce[0], acc_balance};

            if (account_alloc_json.contains("code")) {
                const auto acc_code{from_hex(std::string(account_alloc_json.at("code"))).value()};
                const auto acc_codehash{std::bit_cast<evmc_bytes32>(keccak256(acc_code))};
                account.code_hash = acc_codehash;
                state_buffer->update_account_code(account_address, account.incarnation, acc_codehash, acc_code);
            }

            state_buffer->update_account(account_address, std::nullopt, account);

            if (account_alloc_json.contains("storage")) {
                for (const auto& storage_json : account_alloc_json.at("storage").items()) {
                    Bytes key{from_hex(storage_json.key()).value()};
                    Bytes value{from_hex(storage_json.value().get<std::string>()).value()};
                    state_buffer->update_storage(account_address, account.incarnation, to_bytes32(key), /*initial=*/{}, to_bytes32(value));

                    // FIX 1: update storage on-fly
                    Bytes prefix{silkworm::db::storage_prefix(account_address, account.incarnation)};
                    upsert_storage_value(*state_table_storage, prefix, key, value);
                }
            }
        }

        // Write allocations to db - no changes only accounts
        auto state_table{db::open_cursor(txn, db::table::kPlainState)};
        auto code_table{db::open_cursor(txn, db::table::kCode)};
        for (const auto& [address, account] : state_buffer->accounts()) {
            // Store account plain state
            Bytes encoded{account.encode_for_storage()};
            state_table.upsert(db::to_slice(address), db::to_slice(encoded));

            // Store code
            if (account.code_hash != kEmptyHash) {
                auto code = state_buffer->read_code(account.code_hash);
                code_table.upsert(db::to_slice(account.code_hash), db::to_slice(code));
            }
        }
    }

    BlockHeader header{read_genesis_header(genesis_json, state_buffer->state_root_hash())};
    BlockBody block_body{
        .withdrawals = std::vector<silkworm::Withdrawal>{0},
    };

    // FIX 2: set empty receipts root, should be done in the main code, requires https://github.com/torquem-ch/silkworm/issues/1348
    header.withdrawals_root = kEmptyRoot;

    auto block_hash{header.hash()};
    auto block_hash_key{db::block_key(header.number, block_hash.bytes)};
    db::write_header(txn, header, /*with_header_numbers=*/true);            // Write table::kHeaders and table::kHeaderNumbers
    db::write_canonical_header_hash(txn, block_hash.bytes, header.number);  // Insert header hash as canonical
    db::write_total_difficulty(txn, block_hash_key, header.difficulty);     // Write initial difficulty

    db::write_body(txn, block_body, block_hash.bytes, header.number);  // Write block body (empty)
    db::write_head_header_hash(txn, block_hash.bytes);                 // Update head header in config

    const uint8_t genesis_null_receipts[] = {0xf6};  // <- cbor encoded
    db::open_cursor(txn, db::table::kBlockReceipts)
        .upsert(db::to_slice(block_hash_key).safe_middle(0, 8), db::to_slice(Bytes(genesis_null_receipts, 1)));

    // Write Chain Settings
    auto config_data{genesis_json["config"].dump()};
    db::open_cursor(txn, db::table::kConfig)
        .upsert(db::to_slice(block_hash), mdbx::slice{config_data.data()});

    return state_buffer;
}

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir, std::unique_ptr<InMemoryState>& state_buffer) {
    auto rlp_path = tests_dir / "chain.rlp";
    std::ifstream file(rlp_path, std::ios::binary);
    if (!file) {
        throw std::logic_error("Failed to open the file: " + rlp_path.string());
    }
    std::vector<Bytes> rlps;
    std::vector<uint8_t> line;

    std::basic_string<uint8_t> rlp_buffer(std::istreambuf_iterator<char>(file), {});
    file.close();
    ByteView rlp_view{rlp_buffer};

    auto chain_config = db::read_chain_config(txn);

    if (!chain_config.has_value()) {
        throw std::logic_error("Failed to read chain config");
    }
    auto ruleSet = protocol::rule_set_factory(*chain_config);

    while (rlp_view.length() > 0) {
        silkworm::Block block;

        if (!silkworm::rlp::decode(rlp_view, block, silkworm::rlp::Leftover::kAllow)) {
            throw std::logic_error("Failed to decode RLP file");
        }

        // store original hashes
        auto block_hash = block.header.hash();
        auto block_hash_key = db::block_key(block.header.number, block_hash.bytes);

        // FIX 3: populate senders table
        for (auto& block_txn : block.transactions) {
            block_txn.recover_sender();
        }
        db::write_senders(txn, block_hash, block.header.number, block);

        // FIX 4a: populate tx lookup table and create receipts
        db::write_tx_lookup(txn, block);

        // FIX 4b: populate receipts and logs table
        std::vector<silkworm::Receipt> receipts;
        ExecutionProcessor processor{block, *ruleSet, *state_buffer, *chain_config};
        db::Buffer db_buffer{txn, 0};
        for (auto& block_txn : block.transactions) {
            silkworm::Receipt receipt{};
            processor.execute_transaction(block_txn, receipt);
            receipts.emplace_back(receipt);
        }
        processor.evm().state().write_to_db(block.header.number);
        db_buffer.insert_receipts(block.header.number, receipts);
        db_buffer.write_history_to_db();

        // FIX 5: insert system transactions
        intx::uint256 max_priority_fee_per_gas = block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_priority_fee_per_gas;
        intx::uint256 max_fee_per_gas = block.transactions.empty() ? block.header.base_fee_per_gas.value_or(0) : block.transactions[0].max_fee_per_gas;
        silkworm::Transaction system_transaction;
        system_transaction.max_priority_fee_per_gas = max_priority_fee_per_gas;
        system_transaction.max_fee_per_gas = max_fee_per_gas;
        block.transactions.emplace(block.transactions.begin(), system_transaction);
        block.transactions.emplace_back(system_transaction);

        db::write_header(txn, block.header, /*with_header_numbers=*/true);            // Write table::kHeaders and table::kHeaderNumbers
        db::write_canonical_header_hash(txn, block_hash.bytes, block.header.number);  // Insert header hash as canonical

        // TODO: find how to decode total difficulty
        // db::write_total_difficulty(txn, block_hash_key, block.header.difficulty);     // Write initial difficulty
        db::write_total_difficulty(txn, block_hash_key, 1);  // Write initial difficulty

        db::write_raw_body(txn, block, block_hash, block.header.number);
        db::write_head_header_hash(txn, block_hash.bytes);  // Update head header in config
        db::write_last_head_block(txn, block_hash);         // Update head block in config
        db::write_last_safe_block(txn, block_hash);         // Update last safe block in config
        db::write_last_finalized_block(txn, block_hash);    // Update last finalized block in config
    }
}

class RequestHandler_ForTest : public silkworm::rpc::http::RequestHandler {
  public:
    RequestHandler_ForTest(boost::asio::ip::tcp::socket& socket,
                           commands::RpcApi& rpc_api,
                           const commands::RpcApiTable& rpc_api_table,
                           std::optional<std::string> jwt_secret)
        : silkworm::rpc::http::RequestHandler(socket, rpc_api, rpc_api_table, allowed_origins, std::move(jwt_secret)) {
    }

    Task<void> request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply) {
        co_await RequestHandler::handle_request_and_create_reply(request_json, reply);
    }

    Task<void> handle_request(const std::string& request_str, http::Reply& reply) {
        http::Request request;
        request.content = request_str;
        co_await RequestHandler::handle(request);
        reply = std::move(reply_);
    }

    // Override required to avoid writing to socket and to intercept the reply
    Task<void> do_write(http::Reply& reply) override {
        try {
            reply.headers.emplace_back(http::Header{"Content-Length", std::to_string(reply.content.size())});
            reply.headers.emplace_back(http::Header{"Content-Type", "application/json"});

            reply_ = std::move(reply);
        } catch (const boost::system::system_error& se) {
            std::rethrow_exception(std::make_exception_ptr(se));
        } catch (const std::exception& e) {
            std::rethrow_exception(std::make_exception_ptr(e));
        }
        co_return;
    }

  private:
    inline static const std::vector<std::string> allowed_origins;
    http::Reply reply_;
};

class LocalContextTestBase : public silkworm::rpc::test::ContextTestBase {
  public:
    explicit LocalContextTestBase(const std::shared_ptr<mdbx::env_managed>& chaindata_env) : ContextTestBase() {
        add_private_service<ethdb::Database>(io_context_, std::make_unique<ethdb::file::LocalDatabase>(chaindata_env));
    }
};

template <typename TestRequestHandler>
class RpcApiTestBase : public LocalContextTestBase {
  public:
    explicit RpcApiTestBase(const std::shared_ptr<mdbx::env_managed>& chaindata_env) : LocalContextTestBase(chaindata_env), workers_{1}, socket{io_context_}, rpc_api{io_context_, workers_}, rpc_api_table{kDefaultEth1ApiSpec} {
    }

    template <auto method, typename... Args>
    auto run(Args&&... args) {
        TestRequestHandler handler{socket, rpc_api, rpc_api_table, ""};
        return spawn_and_wait((handler.*method)(std::forward<Args>(args)...));
    }

    boost::asio::thread_pool workers_;
    boost::asio::ip::tcp::socket socket;
    commands::RpcApi rpc_api;
    commands::RpcApiTable rpc_api_table;
};

// Function to recursively sort JSON arrays
void sort_array(nlohmann::json& jsonObj) {  // NOLINT(*-no-recursion)
    if (jsonObj.is_array()) {
        // Sort the elements within the array
        std::sort(jsonObj.begin(), jsonObj.end(), [](const nlohmann::json& a, const nlohmann::json& b) {
            return a.dump() < b.dump();
        });

        // Recursively sort nested arrays
        for (auto& item : jsonObj) {
            sort_array(item);
        }
    } else if (jsonObj.is_object()) {
        for (auto& item : jsonObj.items()) {
            sort_array(item.value());
        }
    }
}

}  // namespace silkworm::rpc::test