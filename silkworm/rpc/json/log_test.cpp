// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_exception.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/util.hpp>

namespace {
#ifdef _WIN32
constexpr const char* kInvalidArgumentMessage = "invalid argument";
#else
constexpr const char* kInvalidArgumentMessage = "Invalid argument";
#endif
}  // namespace

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using std::string_literals::operator""s;

TEST_CASE("serialize empty log", "[rpc][to_json]") {
    Log l{{}, {}, {}};
    nlohmann::json j = l;
    CHECK(j == R"({
        "address":"0x0000000000000000000000000000000000000000",
        "topics":[],
        "data":"0x",
        "blockNumber":"0x0",
        "blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionIndex":"0x0",
        "logIndex":"0x0",
        "removed":false
    })"_json);
}

TEST_CASE("shortest hex for 4206337", "[rpc][to_json]") {
    Log l{{}, {}, {}, 4206337};
    nlohmann::json j = l;
    CHECK(j == R"({
        "address":"0x0000000000000000000000000000000000000000",
        "topics":[],
        "data":"0x",
        "blockNumber":"0x402f01",
        "blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionIndex":"0x0",
        "logIndex":"0x0",
        "removed":false
    })"_json);
}

TEST_CASE("deserialize wrong size log", "[rpc][from_json]") {
    const auto j1 = nlohmann::json::from_cbor(*silkworm::from_hex("80"));
    CHECK_THROWS_MATCHES(j1.get<Log>(), std::system_error, Message("Log CBOR: missing entries: "s + kInvalidArgumentMessage));
    const auto j2 = nlohmann::json::from_cbor(*silkworm::from_hex("81540000000000000000000000000000000000000000"));
    CHECK_THROWS_MATCHES(j2.get<Log>(), std::system_error, Message("Log CBOR: missing entries: "s + kInvalidArgumentMessage));
    const auto j3 = nlohmann::json::from_cbor(*silkworm::from_hex("8254000000000000000000000000000000000000000080"));
    CHECK_THROWS_MATCHES(j3.get<Log>(), std::system_error, Message("Log CBOR: missing entries: "s + kInvalidArgumentMessage));
    const auto j4 = nlohmann::json::from_cbor(*silkworm::from_hex("83808040"));
    CHECK_THROWS_MATCHES(j4.get<Log>(), std::system_error, Message("Log CBOR: binary expected in [0]: "s + kInvalidArgumentMessage));
    const auto j5 = nlohmann::json::from_cbor(*silkworm::from_hex("835400000000000000000000000000000000000000004040"));
    CHECK_THROWS_MATCHES(j5.get<Log>(), std::system_error, Message("Log CBOR: array expected in [1]: "s + kInvalidArgumentMessage));
    const auto j6 = nlohmann::json::from_cbor(*silkworm::from_hex("835400000000000000000000000000000000000000008080"));
    CHECK_THROWS_MATCHES(j6.get<Log>(), std::system_error, Message("Log CBOR: binary or null expected in [2]: "s + kInvalidArgumentMessage));
}

TEST_CASE("deserialize empty array log", "[rpc][from_json]") {
    const auto j1 = nlohmann::json::from_cbor(*silkworm::from_hex("835400000000000000000000000000000000000000008040"));
    const auto log1 = j1.get<Log>();
    CHECK(log1.address == evmc::address{});
    CHECK(log1.topics.empty());
    CHECK(log1.data.empty());
    const auto j2 = nlohmann::json::from_cbor(*silkworm::from_hex("8354000000000000000000000000000000000000000080f6"));
    const auto log2 = j2.get<Log>();
    CHECK(log2.address == evmc::address{});
    CHECK(log2.topics.empty());
    CHECK(log2.data.empty());
}

TEST_CASE("deserialize empty log", "[rpc][from_json]") {
    const auto j = R"({
        "address":"0000000000000000000000000000000000000000",
        "topics":[],
        "data":[]
    })"_json;
    const auto log = j.get<Log>();
    CHECK(log.address == evmc::address{});
    CHECK(log.topics.empty());
    CHECK(log.data.empty());
}

TEST_CASE("deserialize array log", "[rpc][from_json]") {
    const Bytes bytes = silkworm::from_hex("8354ea674fdde714fd979de3edf0f56aa9716b898ec88043010043").value();
    const auto j = nlohmann::json::from_cbor(bytes);
    const auto log = j.get<Log>();
    CHECK(log.address == 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address);
    CHECK(log.topics.empty());
    CHECK(log.data == silkworm::Bytes{0x01, 0x00, 0x43});
}

TEST_CASE("deserialize topics", "[rpc][from_json]") {
    auto j1 = R"({
        "address":"0000000000000000000000000000000000000000",
        "topics":["0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"],
        "data":[]
    })"_json;
    auto f1 = j1.get<Log>();
    CHECK(f1.address == evmc::address{});
    CHECK(f1.topics == std::vector<evmc::bytes32>{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32});
    CHECK(f1.data.empty());
}

TEST_CASE("make empty glaze Log", "[make_glaze_content(Log)]") {
    std::string json;
    std::vector<Log> log{};
    make_glaze_json_content(1, log, json);
    CHECK(strcmp(json.c_str(),
                 "[{\"jsonrpc\":\"2.0\",\
                  \"id\":1,\
                   \"result\":[]}]"));
}

}  // namespace silkworm::rpc
