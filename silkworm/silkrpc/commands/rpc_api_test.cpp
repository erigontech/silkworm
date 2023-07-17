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

#include <fstream>
#include <iostream>
#include <thread>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/types/block.hpp>
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
            std::cerr << "Failed to open the file." << std::endl;
            throw "dupa";
        }

        for (auto& block_txn : block.transactions) {
            block_txn.recover_sender();
        }

        auto block_hash = block.header.hash();
        auto block_hash_key = db::block_key(block.header.number, block_hash.bytes);

        db::write_header(txn, block.header, /*with_header_numbers=*/true);            // Write table::kHeaders and table::kHeaderNumbers
        db::write_canonical_header_hash(txn, block_hash.bytes, block.header.number);  // Insert header hash as canonical
        db::write_total_difficulty(txn, block_hash_key, block.header.difficulty);     // Write initial difficulty
        db::write_body(txn, block, block_hash, block.header.number);
        db::write_senders(txn, block_hash, block.header.number, block);
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

TEST_CASE("rpc_api load state", "[silkrpc][rpc_api][global]") {
    auto db = open_db();
    db::RWTxn txn{*db};
    db::table::check_or_create_chaindata_tables(txn);
    populate_genesis(txn);
    populate_blocks(txn);
    txn.commit_and_stop();

    // Set schema version
    //    silkworm::db::VersionBase v{3, 0, 0};
    //    db::write_schema_version(txn, v);

    RpcApiTestBase<RequestHandler_ForTest> test_base{db};

    SECTION("wrapper") {
        SECTION("test1") {
            auto request = R"({"jsonrpc":"2.0","id":1,"method":"eth_getBlockTransactionCountByHash","params":["0xfe21bb173f43067a9f90cfc59bbb6830a7a2929b5de4a61f372a9db28e87f9ae"]})"_json;
            http::Reply reply;

            test_base.run<&RequestHandler_ForTest::request_and_create_reply>(request, reply);
            CHECK(nlohmann::json::parse(reply.content) == R"({"jsonrpc":"2.0","id":1,"result":"0x1"})"_json);
        }

        SECTION("test2") {
            auto request = R"({"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0xaa00000000000000000000000000000000000000","latest"]})"_json;
            http::Reply reply;
            test_base.run<&RequestHandler_ForTest::request_and_create_reply>(request, reply);
            CHECK(nlohmann::json::parse(reply.content) == R"({"jsonrpc":"2.0","id":1,"result":"0x6042"})"_json);
        }
    }

    db->close();
}

}  // namespace silkworm::rpc::commands
