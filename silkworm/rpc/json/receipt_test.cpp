// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

TEST_CASE("deserialize wrong receipt", "[rpc][from_json]") {
    const nlohmann::json j = R"({})"_json;
    CHECK_THROWS(j.get<Receipt>());
}

TEST_CASE("deserialize empty receipt", "[rpc][from_json]") {
    const nlohmann::json j = R"({"success":false,"cumulative_gas_used":0})"_json;
    const auto r = j.get<Receipt>();
    CHECK(r.success == false);
    CHECK(r.cumulative_gas_used == 0);
}

TEST_CASE("deserialize wrong array receipt", "[rpc][from_json]") {
    CHECK_THROWS_AS(R"([])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([""])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([null])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,""])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,""])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,null])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"(["",null,0,0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,"",0,0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,"",0])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,0,""])"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"([0,null,0,null])"_json.get<Receipt>(), std::system_error);
}

TEST_CASE("deserialize wrong object receipt", "[rpc][from_json]") {
    CHECK_THROWS_AS(R"({})"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"({"result_success":false,"cumulative_gas_used":"0"})"_json.get<Receipt>(), std::system_error);
    CHECK_THROWS_AS(R"({"success":false,"result_cumulative_gas_used":"0"})"_json.get<Receipt>(), std::system_error);
}

TEST_CASE("deserialize empty array receipt", "[rpc][from_json]") {
    const nlohmann::json j1 = R"([0,null,0,0])"_json;
    const auto r1 = j1.get<Receipt>();
    CHECK(r1.type == TransactionType::kLegacy);
    CHECK(r1.success == false);
    CHECK(r1.cumulative_gas_used == 0);
    const auto j2 = nlohmann::json::from_cbor(*silkworm::from_hex("8400f60000"));
    const auto r2 = j2.get<Receipt>();
    CHECK(r2.type == TransactionType::kLegacy);
    CHECK(r2.success == false);
    CHECK(r2.cumulative_gas_used == 0);
}

TEST_CASE("deserialize array receipt", "[rpc][from_json]") {
    const nlohmann::json j = R"([1,null,1,123456])"_json;
    const auto r = j.get<Receipt>();
    CHECK(r.type == TransactionType::kAccessList);
    CHECK(r.success == true);
    CHECK(r.cumulative_gas_used == 123456);
}

TEST_CASE("serialize empty receipt", "[silkworm::json][to_json]") {
    Receipt r{};
    nlohmann::json j = r;
    CHECK(j == R"({
        "blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "blockNumber":"0x0",
        "contractAddress":null,
        "cumulativeGasUsed":"0x0",
        "effectiveGasPrice":"0x0",
        "from":"0x0000000000000000000000000000000000000000",
        "gasUsed":"0x0",
        "logs":[],
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status":"0x0",
        "to":null,
        "transactionHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactionIndex":"0x0",
        "type":"0x0"
    })"_json);
}

TEST_CASE("serialize receipt", "[silkworm::json][to_json]") {
    Receipt r{
        TransactionType::kAccessList,
        true,
        454647,
        silkworm::Bloom{},
        Logs{},
        0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32,
        0x0715a7794a1dc8e42615f059dd6e406a6594651a_address,
        10,
        0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f_bytes32,
        5000000,
        3,
        0x22ea9f6b28db76a7162054c05ed812deb2f519cd_address,
        0x22ea9f6b28db76a7162054c05ed812deb2f519cd_address,
        2000000000};
    nlohmann::json j = r;
    CHECK(j == R"({
        "blockHash":"0xb02a3b0ee16c858afaa34bcd6770b3c20ee56aa2f75858733eb0e927b5b7126f",
        "blockNumber":"0x4c4b40",
        "contractAddress":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "cumulativeGasUsed":"0x6eff7",
        "effectiveGasPrice":"0x77359400",
        "from":"0x22ea9f6b28db76a7162054c05ed812deb2f519cd",
        "gasUsed":"0xa",
        "logs":[],
        "logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(000000000000000000000000000000000000000000000000000000000000000000000000)"
               R"(00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status":"0x0",
        "status":"0x1",
        "to":"0x22ea9f6b28db76a7162054c05ed812deb2f519cd",
        "transactionHash":"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c",
        "transactionIndex":"0x3",
        "type":"0x1"
    })"_json);
}

}  // namespace silkworm::rpc
