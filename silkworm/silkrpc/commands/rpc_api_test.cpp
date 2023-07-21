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
#include <thread>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/genesis.hpp>
#include <silkworm/silkrpc/ethdb/file/local_database.hpp>
#include <silkworm/silkrpc/http/request_handler.hpp>
#include <silkworm/silkrpc/test/api_test_base.hpp>
#include <silkworm/silkrpc/test/context_test_base.hpp>

#include "silkworm/silkrpc/common/constants.hpp"

namespace silkworm::rpc::commands {

using boost::asio::awaitable;
using Catch::Matchers::Message;

std::shared_ptr<mdbx::env_managed> open_db() {
    //        std::string chaindata_dir{DataDirectory{}.chaindata().path().string()};
    std::string chaindata_dir{TemporaryDirectory::get_unique_temporary_path()};
    INFO("chaindata_dir: " << chaindata_dir);

    db::EnvConfig chain_conf{
        .path = chaindata_dir,
        .create = true,
        .exclusive = true,
        .in_memory = true,
        .shared = false};

    return std::make_shared<mdbx::env_managed>(db::open_env(chain_conf));
}

void populate_genesis(db::RWTxn& txn) {
    std::string genesis_json_path = "/home/jacek/dev/ethereum-execution-apis/tests/genesis.json";
    std::ifstream genesis_json_input_file(genesis_json_path);
    nlohmann::json genesis_json;
    genesis_json_input_file >> genesis_json;
    db::initialize_genesis(txn, genesis_json, /*allow_exceptions=*/false);
}

void populate_blocks(db::RWTxn& txn) {
    std::string rlp_path = "/home/jacek/dev/ethereum-execution-apis/tests/chain.rlp";
    std::ifstream file(rlp_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open the file." << std::endl;
        throw "dupa";
    }
    std::vector<Bytes> rlps;
    std::vector<uint8_t> line;

    std::basic_string<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    ByteView view{buffer};

    while (view.length() > 0) {
        silkworm::Block block;

        if (!silkworm::rlp::decode(view, block, silkworm::rlp::Leftover::kAllow)) {
            throw "Failed to decode RLP file";
        }

        // store original hashes
        auto block_hash = block.header.hash();
        auto block_hash_key = db::block_key(block.header.number, block_hash.bytes);

        // FIX 1: populate senders table
        for (auto& block_txn : block.transactions) {
            block_txn.recover_sender();

            auto th = to_hex_no_leading_zeros(block_txn.hash());
            auto th2 = to_hex_no_leading_zeros(hash_of_transaction(block_txn).bytes);
            std::cout << "th: " << th << " th2: " << th2 << std::endl;
        }
        db::write_senders(txn, block_hash, block.header.number, block);

        // FIX 2: populate tx lookup table and create receipts
        std::vector<silkworm::Receipt> receipts;
        uint64_t cumulative_gas_used = 0;
        for (auto& block_txn : block.transactions) {
            db::write_tx_lookup(txn, block_txn.hash(), block.header.number, block);

            silkworm::Receipt receipt;
            cumulative_gas_used += block_txn.gas_limit;
            receipt.type = block_txn.type;
            receipt.success = true;
            receipt.cumulative_gas_used = cumulative_gas_used;
            receipt.bloom = block.header.logs_bloom;
            receipts.emplace_back(receipt);
        }
        db::write_receipts(txn, receipts, block.header.number);

        // FIX 3: insert system transactions
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

        //        db::write_canonical_hash(txn, block_hash_key);      // Insert block hash as canonical
    }
}

class RequestHandler_ForTest : public silkworm::rpc::http::RequestHandler {
  public:
    RequestHandler_ForTest(boost::asio::ip::tcp::socket& socket,
                           commands::RpcApi& rpc_api,
                           const commands::RpcApiTable& rpc_api_table,
                           std::optional<std::string> jwt_secret)
        : silkworm::rpc::http::RequestHandler(socket, rpc_api, rpc_api_table, jwt_secret) {
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

TEST_CASE("rpc_api io", "[silkrpc][rpc_api]") {
    auto workingDir = std::filesystem::current_path();
    // std::cout << "Current path is " << workingDir << '\n';

    while (!std::filesystem::exists(workingDir / "third_party" / "execution-apis") && workingDir != "/") {
        workingDir = workingDir.parent_path();
    }

    REQUIRE(std::filesystem::exists(workingDir / "third_party" / "execution-apis"));

    auto testsDir = workingDir / "third_party" / "execution-apis" / "tests";

    auto db = open_db();
    db::RWTxnManaged txn{*db};
    db::table::check_or_create_chaindata_tables(txn);
    populate_genesis(txn);
    populate_blocks(txn);
    txn.commit_and_stop();

    // Set schema version
    //    silkworm::db::VersionBase v{3, 0, 0};
    //    db::write_schema_version(txn, v);

    RpcApiTestBase<RequestHandler_ForTest> test_base{db};

    for (const auto& test_file : std::filesystem::recursive_directory_iterator(testsDir)) {
        if (!test_file.is_directory() && test_file.path().extension() == ".io") {
            // std::cout << "Running test " << test_file.path() << std::endl;
            auto test_name = test_file.path().filename().string();
            auto group_name = test_file.path().parent_path().filename().string();

            std::ifstream test_stream(test_file.path());

            if (!test_stream.is_open()) {
                std::cerr << "Failed to open the file." << std::endl;
                throw "dupa";
            }

            SECTION("RPC IO test " + group_name + "|" + test_name) {
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
                    CHECK(nlohmann::json::parse(reply.content) == expected);
                }
            }
        }
    }

    db->close();
}

TEST_CASE("rpc_api io (individual)", "[silkrpc][rpc_api]") {
    auto db = open_db();
    db::RWTxnManaged txn{*db};
    db::table::check_or_create_chaindata_tables(txn);
    populate_genesis(txn);
    populate_blocks(txn);
    txn.commit_and_stop();

    // Set schema version
    //    silkworm::db::VersionBase v{3, 0, 0};
    //    db::write_schema_version(txn, v);

    RpcApiTestBase<RequestHandler_ForTest> test_base{db};

    SECTION("sample test") {
        auto request = R"({"id":1,"jsonrpc":"2.0","method":"eth_getStorageAt","params":["0xaa00000000000000000000000000000000000000","0x0100000000000000000000000000000000000000000000000000000000000000","latest"]})"_json;
        http::Reply reply;

        test_base.run<&RequestHandler_ForTest::request_and_create_reply>(request, reply);
        CHECK(nlohmann::json::parse(reply.content) == R"({"id":1,"jsonrpc":"2.0","result":"0x0100000000000000000000000000000000000000000000000000000000000000"})"_json);
    }

    db->close();
}

}  // namespace silkworm::rpc::commands
