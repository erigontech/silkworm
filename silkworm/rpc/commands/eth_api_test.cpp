// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/rpc/test_util/api_test_database.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_blockNumber succeeds if request well-formed", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result":"0x9"
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_blockNumber fails if request empty", "[rpc][api]") {
    const nlohmann::json request = R"({})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":null,
        "error":{"code":-32600,"message":"invalid request"}
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_sendRawTransaction fails rlp parsing", "[rpc][api]") {
    const nlohmann::json request = R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": ["0xd46ed67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f0724456"]
    })"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{"code":-32000,"message":"rlp: input exceeds encoded length"}
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_sendRawTransaction fails length", "[rpc][api]") {
    const nlohmann::json request = R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": ["0x01f87482053980843b9aca008509502f9000830493e080809a608060405260098060116000396000f3fe6080604052600080fdc001a02f770992b74b52f9e2beef5b33376590e6dc7669ee7ab648e1e31ad3a377f627a07c3030ba71736bb982ccbb1e36b073489abe0c18ffc14be5206c29f1c026c99a"]
    })"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{"code":-32000,"message":"rlp: unexpected Length"}
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_sendRawTransaction fails to send", "[rpc][api]") {
    const nlohmann::json request = R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_sendRawTransaction",
        "params": ["0x02f87482053980843b9aca008509502f9000830493e080809a608060405260098060116000396000f3fe6080604052600080fdc001a02f770992b74b52f9e2beef5b33376590e6dc7669ee7ab648e1e31ad3a377f627a07c3030ba71736bb982ccbb1e36b073489abe0c18ffc14be5206c29f1c026c99a"]
    })"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    auto reply_json = nlohmann::json::parse(reply);
    CHECK(reply_json["jsonrpc"] == "2.0");
    CHECK(reply_json["id"] == 1);
    REQUIRE(reply_json["error"].is_object());
    CHECK(reply_json["error"]["code"] == 100);
    CHECK_THAT(reply_json["error"]["message"], Catch::Matchers::StartsWith("failed to connect to all addresses; last error: UNKNOWN: ipv4:127.0.0.1:12345: Failed to connect to remote host"));
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "unit: eth_feeHistory succeeds if request well-formed", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1","0x867A80",[25,75]]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result":{"baseFeePerBlobGas":["0x0","0x0"],"baseFeePerGas":["0x0","0x0"],"blobGasUsedRatio":[0.0],"gasUsedRatio":[0.0],"oldestBlock":"0x867a80","reward":[[]]}
    })"_json);
}

#ifdef notdef  // temporarily commented out waiting for LocalTransaction implementation
TEST_CASE_METHOD(test_util::RpcApiE2ETest, "eth_call without params on gas", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{}, "latest"]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result":"0x"
   })"_json);
}
#endif

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "fuzzy: eth_feeHistory sigsegv invalid input", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["5x1","0x2",[95,99]]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "error":{"code":100,"message":"invalid block_count: 5x1"}
    })"_json);
}

TEST_CASE_METHOD(test_util::RpcApiE2ETest, "fuzzy: eth_feeHistory sigsegv valid input", "[rpc][api]") {
    const nlohmann::json request = R"({"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x5","0x2",[95,99]]})"_json;
    std::string reply;
    run<&test_util::RequestHandlerForTest::request_and_create_reply>(request, reply);
    CHECK(nlohmann::json::parse(reply) == R"({
        "jsonrpc":"2.0",
        "id":1,
        "result":{
            "baseFeePerBlobGas":["0x0","0x0","0x0","0x0"],
            "baseFeePerGas":["0x3b9aca00","0x342770c0","0x2db08786","0x2806be9d"],
            "blobGasUsedRatio":[0.0,0.0,0.0],
            "gasUsedRatio":[0.0,0.0042,0.0042],
            "oldestBlock":"0x0",
            "reward":[["0x0","0x0"],["0x1","0x1"],["0x1","0x1"]]}
    })"_json);
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
