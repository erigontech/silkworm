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

#include "eth_api.hpp"

#include <thread>

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/test/api_test_base.hpp>
#include <silkworm/rpc/test/api_test_database.hpp>

namespace silkworm::rpc::commands {

//! Utility class to expose handle hooks publicly just for tests
class EthereumRpcApi_ForTest : public EthereumRpcApi {
  public:
    explicit EthereumRpcApi_ForTest(boost::asio::io_context& ioc, boost::asio::thread_pool& workers)
        : EthereumRpcApi{ioc, workers} {}

    // MSVC doesn't support using access declarations properly, so explicitly forward these public accessors
    Task<void> eth_block_number(const nlohmann::json& request, nlohmann::json& reply) {
        co_await EthereumRpcApi::handle_eth_block_number(request, reply);
    }
    Task<void> eth_send_raw_transaction(const nlohmann::json& request, nlohmann::json& reply) {
        co_await EthereumRpcApi::handle_eth_send_raw_transaction(request, reply);
    }
};

using EthereumRpcApiTest = test::JsonApiWithWorkersTestBase<EthereumRpcApi_ForTest>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(EthereumRpcApiTest, "handle_eth_block_number succeeds if request well-formed", "[rpc][eth_api]") {
    nlohmann::json reply;

    // TODO(canepat) we need to mock silkworm::core functions properly, then we must change this check
    CHECK_THROWS_AS(run<&EthereumRpcApi_ForTest::eth_block_number>(
                        R"({
                            "jsonrpc":"2.0",
                            "id": 1,
                            "method":"eth_blockNumber",
                            "params":[]
                        })"_json,
                        reply),
                    std::exception);
    /*CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "result":{}
        })"_json);*/
}

TEST_CASE_METHOD(EthereumRpcApiTest, "handle_eth_block_number fails if request empty", "[rpc][eth_api]") {
    nlohmann::json reply;

    // TODO(canepat) we need to mock silkworm::core functions properly, then we must change this check
    CHECK_THROWS_AS(run<&EthereumRpcApi_ForTest::eth_block_number>(R"({})"_json, reply), std::exception);
    /*CHECK(reply == R"({
            "jsonrpc":"2.0",
            "id":1,
            "result":{}
        })"_json);*/
}

TEST_CASE_METHOD(EthereumRpcApiTest, "handle_eth_send_raw_transaction fails rlp parsing", "[rpc][eth_api]") {
    nlohmann::json reply;

    run<&EthereumRpcApi_ForTest::eth_send_raw_transaction>(
        R"({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": ["0xd46ed67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f0724456"]
        })"_json,
        reply);
    CHECK(reply == R"({
        "error":{"code":-32000,"message":"rlp: input exceeds encoded length"},"id":1,"jsonrpc":"2.0"
    })"_json);
}

TEST_CASE_METHOD(EthereumRpcApiTest, "handle_eth_send_raw_transaction fails wrong number digit", "[rpc][eth_api]") {
    nlohmann::json reply;

    run<&EthereumRpcApi_ForTest::eth_send_raw_transaction>(
        R"({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": ["0xd46ed67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445"]
        })"_json,
        reply);
    CHECK(reply == R"({
        "error":{"code":-32000,"message":"rlp: unexpected EIP-2178 serialization"},"id":1,"jsonrpc":"2.0"
    })"_json);
}

TEST_CASE("fuzzy: eth_call invalid params", "[rpc][api]") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    auto context = test::TestDatabaseContext();
    test::RpcApiTestBase<test::RequestHandler_ForTest> handler{context.db};

    const auto request = R"({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{}, "latest"]})"_json;

    http::Reply reply;
    handler.run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply.content) == R"({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"malformed transaction: cannot recover sender"}})"_json);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
