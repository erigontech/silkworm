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

#include "request_handler.hpp"

#include <catch2/catch.hpp>

#include <silkworm/rpc/test/api_test_database.hpp>

namespace silkworm::rpc::http {

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(test::RpcApiE2ETest, "check handle_request no method", "[rpc][handle]") {
    const auto request = R"({"jsonrpc":"2.0","id":1})"_json;
    std::string reply;
    run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{
             "code":-32600,
             "message":"invalid request"
        }
    })"_json);
}

TEST_CASE_METHOD(test::RpcApiE2ETest, "check handle_request invalid method", "[rpc][handle_request]") {
    const auto request = R"({"jsonrpc":"2.0","id":1, "method":"eth_AAA"})"_json;
    std::string reply;
    run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{
             "code":-32601,
             "message": "the method eth_AAA does not exist/is not available"
        }
    })"_json);
}

TEST_CASE_METHOD(test::RpcApiE2ETest, "check handle_request method return failed", "[rpc][handle_request]") {
    const auto request = R"({"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":[]})"_json;
    std::string reply;
    run<&test::RequestHandler_ForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":3,
        "error":{
             "code":100,
             "message":"invalid eth_getBlockByNumber params: []"
        }
    })"_json);
}

#endif

}  // namespace silkworm::rpc::http
