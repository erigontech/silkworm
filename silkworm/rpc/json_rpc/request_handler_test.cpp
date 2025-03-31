// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "request_handler.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

namespace silkworm::rpc::json_rpc {

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request no method", "[rpc][handle]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{
             "code":-32600,
             "message":"invalid request"
        }
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request invalid method", "[rpc][handle_request]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1, "method":"eth_AAA"})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{
             "code":-32601,
             "message": "the method eth_AAA does not exist/is not available"
        }
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request method return failed", "[rpc][handle_request]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":3,"method":"eth_getBlockByNumber","params":[]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":3,
        "error":{
             "code":-32602,
             "message":"invalid eth_getBlockByNumber params: []"
        }
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request does not allow nil characters after json object", "[rpc][handle_request]") {
    // request: {"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1A","0x2",[95,99]]}\0x0H
    static constexpr char kBinaryInputInternal[] = {0x7b, 0x22, 0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63, 0x22, 0x3a, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x2c, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x31, 0x2c, 0x22, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x22, 0x3a, 0x22, 0x65, 0x74, 0x68, 0x5f, 0x66, 0x65, 0x65, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x2c, 0x22, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x3a, 0x5b, 0x22, 0x30, 0x78, 0x31, 0x41, 0x22, 0x2c, 0x22, 0x30, 0x78, 0x32, 0x22, 0x2c, 0x5b, 0x39, 0x35, 0x2c, 0x39, 0x39, 0x5d, 0x5d, 0x7d, 0x0, 0x48};
    const std::string_view request_view{&kBinaryInputInternal[0], sizeof(kBinaryInputInternal)};
    const std::string request{request_view};
    std::string reply;
    run<&test_util::RequestHandlerForTest::handle_request>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "error": {
            "code": -32601,
            "message": "invalid request"
        },
        "id": null,
        "jsonrpc": "2.0"
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request does not allow nil characters inside json object", "[rpc][handle_request]") {
    // request: {"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1A","0x2",[95,99]]\0x0}
    static constexpr char kBinaryInputInternal[] = {0x7b, 0x22, 0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63, 0x22, 0x3a, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x2c, 0x22, 0x69, 0x64, 0x22, 0x3a, 0x31, 0x2c, 0x22, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x22, 0x3a, 0x22, 0x65, 0x74, 0x68, 0x5f, 0x66, 0x65, 0x65, 0x48, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x22, 0x2c, 0x22, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x3a, 0x5b, 0x22, 0x30, 0x78, 0x31, 0x41, 0x22, 0x2c, 0x22, 0x30, 0x78, 0x32, 0x22, 0x2c, 0x5b, 0x39, 0x35, 0x2c, 0x39, 0x39, 0x5d, 0x5d, 0x0, 0x7d};
    const std::string_view request_view{&kBinaryInputInternal[0], sizeof(kBinaryInputInternal)};
    const std::string request{request_view};
    std::string reply;
    run<&test_util::RequestHandlerForTest::handle_request>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "error": {
            "code": -32601,
            "message": "invalid request"
        },
        "id": null,
        "jsonrpc": "2.0"
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request does allow nil characters inside quoted string", "[rpc][handle_request]") {
    // request: {"jsonrpc":"2.0","id":1,"method":"eth_feeHistory\0x0","params":["0x1A","0x2",[95,99]]}
    static constexpr char kBinaryInputInternal[] = {
        0x7b, 0x22, 0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63, 0x22, 0x3a, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x2c, 0x22, 0x69, 0x64, 0x22,
        0x3a, 0x31, 0x2c, 0x22, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x22, 0x3a, 0x22, 0x65, 0x74, 0x68, 0x5f, 0x66, 0x65, 0x65, 0x48,
        0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x0, 0x22, 0x2c, 0x22, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x22, 0x3a, 0x5b, 0x22, 0x30,
        0x78, 0x31, 0x41, 0x22, 0x2c, 0x22, 0x30, 0x78, 0x32, 0x22, 0x2c, 0x5b, 0x39, 0x35, 0x2c, 0x39, 0x39, 0x5d, 0x5d, 0x7d};
    const std::string_view request_view{&kBinaryInputInternal[0], sizeof(kBinaryInputInternal)};
    const std::string request{request_view};
    std::string reply;
    run<&test_util::RequestHandlerForTest::handle_request>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "error": {
            "code": -32600,
            "message": "invalid request"
        },
        "id": null,
        "jsonrpc": "2.0"
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "check handle_request does not allow missing params if required", "[rpc][handle_request]") {
    // request: {"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts"}\012
    static constexpr char kBinaryInputInternal[] = {
        0x7b, 0x22, 0x6a, 0x73, 0x6f, 0x6e, 0x72, 0x70, 0x63, 0x22, 0x3a, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x2c, 0x22, 0x69, 0x64, 0x22,
        0x3a, 0x31, 0x2c, 0x22, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x22, 0x3a, 0x22, 0x65, 0x74, 0x68, 0x5f, 0x67, 0x65, 0x74,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x52, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x73, 0x22, 0x7d, 0xa};
    const std::string_view request_view{&kBinaryInputInternal[0], sizeof(kBinaryInputInternal)};
    const std::string request{request_view};
    std::string reply;
    run<&test_util::RequestHandlerForTest::handle_request>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "error": {
            "code": -32600,
            "message": "Missing required parameter: Block"
        },
        "id": 1,
        "jsonrpc": "2.0"
    })"_json);
}

#endif

}  // namespace silkworm::rpc::json_rpc
