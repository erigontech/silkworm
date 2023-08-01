/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "rpc_api.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/silkrpc/ethdb/file/local_database.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>
#include <silkworm/silkrpc/test/context_test_base.hpp>

#include "silkworm/core/common/cast.hpp"
#include "silkworm/silkrpc/common/constants.hpp"

namespace silkworm::rpc::commands {

using boost::asio::awaitable;
using Catch::Matchers::Message;

std::filesystem::path get_tests_dir() {
    auto working_dir = std::filesystem::current_path();

    while (!std::filesystem::exists(working_dir / "third_party" / "execution-apis") && working_dir != "/") {
        working_dir = working_dir.parent_path();
    }

    INFO("initial working_dir: " << std::filesystem::current_path());
    REQUIRE(std::filesystem::exists(working_dir / "third_party" / "execution-apis"));

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

void populate_genesis(db::RWTxn& txn, const std::filesystem::path& tests_dir) {
    auto genesis_json_path = tests_dir / "genesis.json";
    std::ifstream genesis_json_input_file(genesis_json_path);
    nlohmann::json genesis_json;
    genesis_json_input_file >> genesis_json;
    InMemoryState state_buffer{};

    // Allocate accounts
    if (genesis_json.contains("alloc")) {
        auto state_table_storage = txn.rw_cursor_dup_sort(db::table::kPlainState);

        for (const auto& item : genesis_json["alloc"].items()) {
            const auto& account_alloc_json = item.value();

            auto address_bytes{from_hex(item.key())};
            evmc::address account_address = to_evmc_address(*address_bytes);
            const auto acc_balance{intx::from_string<intx::uint256>(account_alloc_json.at("balance"))};

            intx::uint256 acc_nonce{0};
            if (account_alloc_json.contains("nonce")) {
                acc_nonce = intx::from_string<intx::uint256>(account_alloc_json.at("nonce"));
            }

            Account account{acc_nonce[0], acc_balance};

            if (account_alloc_json.contains("code")) {
                const auto acc_code{from_hex(std::string(account_alloc_json.at("code"))).value()};
                const auto acc_codehash{bit_cast<evmc_bytes32>(keccak256(acc_code))};
                account.code_hash = acc_codehash;
                state_buffer.update_account_code(account_address, account.incarnation, acc_codehash, acc_code);
            }

            state_buffer.update_account(account_address, std::nullopt, account);

            if (account_alloc_json.contains("storage")) {
                for (const auto& storage_json : account_alloc_json.at("storage").items()) {
                    Bytes key{from_hex(storage_json.key()).value()};
                    Bytes value{from_hex(storage_json.value().get<std::string>()).value()};
                    state_buffer.update_storage(account_address, account.incarnation, to_bytes32(key), /*initial=*/{}, to_bytes32(value));

                    // FIX 1: update storage on-fly
                    Bytes prefix{silkworm::db::storage_prefix(account_address, account.incarnation)};
                    upsert_storage_value(*state_table_storage, prefix, key, value);
                }
            }
        }

        // Write allocations to db - no changes only accounts
        auto state_table{db::open_cursor(txn, db::table::kPlainState)};
        auto code_table{db::open_cursor(txn, db::table::kCode)};
        for (const auto& [address, account] : state_buffer.accounts()) {
            // Store account plain state
            Bytes encoded{account.encode_for_storage()};
            state_table.upsert(db::to_slice(address), db::to_slice(encoded));

            // Store code
            if (account.code_hash != kEmptyHash) {
                auto code = state_buffer.read_code(account.code_hash);
                code_table.upsert(db::to_slice(account.code_hash), db::to_slice(code));
            }
        }
    }

    BlockHeader header{read_genesis_header(genesis_json, state_buffer.state_root_hash())};
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
        .upsert(db::to_slice(block_hash.bytes), mdbx::slice{config_data.data()});
}

void populate_blocks(db::RWTxn& txn, const std::filesystem::path& tests_dir) {
    auto rlp_path = tests_dir / "chain.rlp";
    std::ifstream file(rlp_path, std::ios::binary);
    if (!file) {
        throw std::logic_error("Failed to open the file: " + rlp_path.string());
    }
    std::vector<Bytes> rlps;
    std::vector<uint8_t> line;

    std::basic_string<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    ByteView view{buffer};

    while (view.length() > 0) {
        silkworm::Block block;

        if (!silkworm::rlp::decode(view, block, silkworm::rlp::Leftover::kAllow)) {
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

        // FIX 4: populate tx lookup table and create receipts
        std::vector<silkworm::Receipt> receipts;
        uint64_t cumulative_gas_used = 0;
        for (auto& block_txn : block.transactions) {
            db::write_tx_lookup(txn, block.header.number, block);
            cumulative_gas_used += block_txn.gas_limit;
            silkworm::Receipt receipt{.type = block_txn.type, .success = true, .cumulative_gas_used = cumulative_gas_used, .bloom = block.header.logs_bloom};
            receipts.emplace_back(receipt);
        }
        db::write_receipts(txn, receipts, block.header.number);

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
        : silkworm::rpc::http::RequestHandler(socket, rpc_api, rpc_api_table, std::move(jwt_secret)) {
    }

    boost::asio::awaitable<void> request_and_create_reply(const nlohmann::json& request_json, http::Reply& reply) {
        co_await RequestHandler::handle_request_and_create_reply(request_json, reply);
    }
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

// Define the static list of strings
static const std::vector<std::string> tests_to_ignore = {
    "eth_estimateGas",         // call to oracle fails, needs fixing
    "debug_getRawReceipts",    // not implemented
    "eth_getProof",            // not implemented
    "eth_feeHistory",          // history not stored, needs fixing
    "eth_sendRawTransaction",  // call to oracle fails, needs fixing or mocking
};

TEST_CASE("rpc_api io", "[silkrpc][rpc_api]") {
    auto tests_dir = get_tests_dir();
    for (const auto& test_file : std::filesystem::recursive_directory_iterator(tests_dir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();

            if (std::find(tests_to_ignore.begin(), tests_to_ignore.end(), group_name) != tests_to_ignore.end()) {
                continue;
            }

            std::ifstream test_stream(test_file.path());

            if (!test_stream.is_open()) {
                FAIL("Failed to open the file: " + test_file.path().string());
            }

            SECTION("RPC IO test " + group_name + " | " + test_name) {
                const auto db_dir = TemporaryDirectory::get_unique_temporary_path();
                auto db = open_db(db_dir);
                db::RWTxnManaged txn{*db};
                db::table::check_or_create_chaindata_tables(txn);
                populate_genesis(txn, tests_dir);
                populate_blocks(txn, tests_dir);
                txn.commit_and_stop();

                RpcApiTestBase<RequestHandler_ForTest> test_base{db};

                std::string line_out;
                std::string line_in;

                while (std::getline(test_stream, line_out) && std::getline(test_stream, line_in)) {
                    if (!line_out.starts_with(">> ") || !line_in.starts_with("<< ")) {
                        FAIL("Invalid test file format");
                    }

                    auto request = nlohmann::json::parse(line_out.substr(3));
                    auto expected = nlohmann::json::parse(line_in.substr(3));

                    http::Reply reply;
                    test_base.run<&RequestHandler_ForTest::request_and_create_reply>(request, reply);
                    INFO("Request: " << request.dump());

                    if (test_name.find("invalid") != std::string::npos) {
                        INFO("Expected error: " << expected.dump());
                        INFO("Actual response: " << reply.content);
                        CHECK(nlohmann::json::parse(reply.content).contains("error"));
                    } else {
                        CHECK(nlohmann::json::parse(reply.content) == expected);
                    }
                }

                db->close();
                std::filesystem::remove_all(db_dir);
            }
        }
    }
}

TEST_CASE("rpc_api io (individual)", "[silkrpc][rpc_api]") {
    const auto tests_dir = get_tests_dir();
    const auto db_dir = TemporaryDirectory::get_unique_temporary_path();
    auto db = open_db(db_dir);
    db::RWTxnManaged txn{*db};
    db::table::check_or_create_chaindata_tables(txn);
    populate_genesis(txn, tests_dir);
    populate_blocks(txn, tests_dir);
    txn.commit_and_stop();

    RpcApiTestBase<RequestHandler_ForTest> test_base{db};

    SECTION("sample test") {
        auto request = R"({"jsonrpc":"2.0","id":1,"method":"debug_getRawTransaction","params":["0x74e41d593675913d6d5521f46523f1bd396dff1891bdb35f59be47c7e5e0b34b"]})"_json;
        http::Reply reply;

        test_base.run<&RequestHandler_ForTest::request_and_create_reply>(request, reply);
        CHECK(nlohmann::json::parse(reply.content) == R"({"jsonrpc":"2.0","id":1,"result":"0xf8678084342770c182520894658bdf435d810c91414ec09147daa6db624063798203e880820a95a0af5fc351b9e457a31f37c84e5cd99dd3c5de60af3de33c6f4160177a2c786a60a0201da7a21046af55837330a2c52fc1543cd4d9ead00ddf178dd96935b607ff9b"})"_json);
    }

    db->close();
    std::filesystem::remove_all(db_dir);
}

}  // namespace silkworm::rpc::commands
