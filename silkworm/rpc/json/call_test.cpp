// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("deserialize null call", "[silkworm::json][from_json]") {
    auto j1 = R"({})"_json;
    CHECK_NOTHROW(j1.get<Call>());
}

TEST_CASE("deserialize minimal call", "[silkworm::json][from_json]") {
    auto j1 = R"({
        "to": "0x0715a7794a1dc8e42615f059dd6e406a6594651a"
    })"_json;
    auto c1 = j1.get<Call>();
    CHECK(c1.from == std::nullopt);
    CHECK(c1.to == evmc::address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address});
    CHECK(c1.gas == std::nullopt);
    CHECK(c1.gas_price == std::nullopt);
    CHECK(c1.max_priority_fee_per_gas == std::nullopt);
    CHECK(c1.max_fee_per_gas == std::nullopt);
    CHECK(c1.value == std::nullopt);
    CHECK(c1.data == std::nullopt);
    CHECK(c1.nonce == std::nullopt);
    CHECK(c1.access_list.empty());
}

TEST_CASE("deserialize full call", "[silkworm::json][from_json]") {
    auto j1 = R"({
        "from": "0x52c24586c31cff0485a6208bb63859290fba5bce",
        "to": "0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "gas": "0xF4240",
        "gasPrice": "0x10C388C00",
        "value": "0x10C388C00",
        "nonce": "0x1",
        "data": "0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000",
        "accessList":[
            {
               "address":"0x52c24586c31cff0485a6208bb63859290fba5bce",
               "storageKeys":["0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"]
            },
            {
               "address": "0x62c24586c31cff0485a6208bb63859290fba5bce",
               "storageKeys":[]
            }
         ]
    })"_json;
    auto c1 = j1.get<Call>();
    CHECK(c1.from == 0x52c24586c31cff0485a6208bb63859290fba5bce_address);
    CHECK(c1.to == 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address);
    CHECK(c1.gas == intx::uint256{1000000});
    CHECK(c1.gas_price == intx::uint256{4499999744});
    CHECK(c1.value == intx::uint256{4499999744});
    CHECK(c1.data == silkworm::from_hex("0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(c1.nonce == intx::uint256{1});
    CHECK(c1.access_list.size() == 2);

    auto j2 = R"({
        "from":"0x52c24586c31cff0485a6208bb63859290fba5bce",
        "to":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "gas":1000000,
        "gasPrice":"0x10C388C00",
        "data":"0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000",
        "value":"0x124F80",
        "nonce": 1
    })"_json;
    auto c2 = j2.get<Call>();
    CHECK(c2.from == 0x52c24586c31cff0485a6208bb63859290fba5bce_address);
    CHECK(c2.to == 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address);
    CHECK(c2.gas == intx::uint256{1000000});
    CHECK(c2.gas_price == intx::uint256{4499999744});
    CHECK(c2.data == silkworm::from_hex("0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(c2.value == intx::uint256{1200000});
    CHECK(c2.nonce == intx::uint256{1});

    auto j3 = R"({
        "from":"0x52c24586c31cff0485a6208bb63859290fba5bce",
        "to":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
        "gas":1000000,
        "gasPrice":"0x10C388C00",
        "input":"0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000",
        "value":"0x124F80",
        "nonce": 1
    })"_json;
    auto c3 = j3.get<Call>();
    CHECK(c3.from == 0x52c24586c31cff0485a6208bb63859290fba5bce_address);
    CHECK(c3.to == 0x0715a7794a1dc8e42615f059dd6e406a6594651a_address);
    CHECK(c3.gas == intx::uint256{1000000});
    CHECK(c3.gas_price == intx::uint256{4499999744});
    CHECK(c3.data == silkworm::from_hex("0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"));
    CHECK(c3.value == intx::uint256{1200000});
    CHECK(c3.nonce == intx::uint256{1});
}

TEST_CASE("make glaze content (data)", "[make_glaze_json_error]") {
    std::string json;
    const char* data_hex{"c68341b58302d066"};
    silkworm::Bytes data_bytes{*silkworm::from_hex(data_hex)};
    make_glaze_json_content(1, data_bytes, json);
    CHECK(strcmp(json.c_str(),
                 "{\"jsonrpc\":\"2.0\",\
                  \"id\":1,\
                   \"result\":\"0xc68341b58302d066\"}"));
}

TEST_CASE("Bundle", "[silkworm::json][from_json]") {
    SECTION("Only 1 transaction") {
        auto json = R"({
            "transactions": [
                {
                    "from":"0x52c24586c31cff0485a6208bb63859290fba5bce",
                    "to":"0x0715a7794a1dc8e42615f059dd6e406a6594651a",
                    "gas":1000000,
                    "gasPrice":"0x10C388C00",
                    "data":"0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000",
                    "value":"0x124F80",
                    "nonce": 1
                }
            ]
        })"_json;

        auto bundle = json.get<Bundle>();

        CHECK(bundle.transactions.size() == 1);

        auto& call = bundle.transactions[0];
        CHECK(call.from == evmc::address{0x52c24586c31cff0485a6208bb63859290fba5bce_address});
        CHECK(call.to == evmc::address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address});
        CHECK(call.gas == intx::uint256{1000000});
        CHECK(call.gas_price == intx::uint256{4499999744});
        CHECK(call.data == silkworm::from_hex("0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"));
        CHECK(call.value == intx::uint256{1200000});
        CHECK(call.nonce == intx::uint256{1});

        auto& bo = bundle.block_override;
        CHECK(bo.block_num == std::nullopt);
        CHECK(bo.coin_base == std::nullopt);
        CHECK(bo.timestamp == std::nullopt);
        CHECK(bo.difficulty == std::nullopt);
        CHECK(bo.gas_limit == std::nullopt);
        CHECK(bo.base_fee == std::nullopt);
    }

    SECTION("2 transaction") {
        auto json = R"({
            "transactions": [
                {
                    "from":"0x52c24586c31cff0485a6208bb63859290fba5bce"
                },
                {
                    "from":"0x52c24586c31cff0485a6208bb63859290fba5baa"
                }
            ]
        })"_json;

        auto bundle = json.get<Bundle>();

        CHECK(bundle.transactions.size() == 2);
        CHECK(bundle.transactions[0].from == evmc::address{0x52c24586c31cff0485a6208bb63859290fba5bce_address});
        CHECK(bundle.transactions[1].from == evmc::address{0x52c24586c31cff0485a6208bb63859290fba5baa_address});
    }

    SECTION("Simple transaction and block overrides") {
        auto json = R"({
            "transactions": [
                {
                    "from":"0x52c24586c31cff0485a6208bb63859290fba5bce"
                }
            ],
            "blockOverride": {
                "blockNumber": 10,
                "coinbase": "0x52c24586c31cff0485a6208bb63859290fba5baa",
                "timestamp": 1000,
                "difficulty": "0x1000000",
                "gasLimit": 3,
                "baseFee": 4
            }
        })"_json;

        auto bundle = json.get<Bundle>();

        CHECK(bundle.transactions.size() == 1);

        auto& call = bundle.transactions[0];
        CHECK(call.from == evmc::address{0x52c24586c31cff0485a6208bb63859290fba5bce_address});

        auto& bo = bundle.block_override;
        CHECK(bo.block_num == 10);
        CHECK(bo.coin_base == evmc::address{0x52c24586c31cff0485a6208bb63859290fba5baa_address});
        CHECK(bo.timestamp == 1000);
        CHECK(bo.difficulty == intx::uint256{16777216});
        CHECK(bo.gas_limit == 3);
        CHECK(bo.base_fee == 4);
    }
}

TEST_CASE("AccountOverrides", "[silkworm::json][from_json]") {
    SECTION("Empty account overrides") {
        auto json = R"({
        })"_json;

        auto state = json.get<AccountOverrides>();
        CHECK(state.balance.has_value() == false);
        CHECK(state.nonce.has_value() == false);
        CHECK(state.code.has_value() == false);
        CHECK(state.state.empty());
        CHECK(state.state_diff.empty());
    }
    SECTION("Full account overrides") {
        auto json = R"({
            "balance": "0x1000000",
            "nonce": 10,
            "code": "0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"
        })"_json;

        auto state = json.get<AccountOverrides>();

        CHECK(state.balance.has_value() == true);
        CHECK(state.balance.value() == intx::uint256{16777216});

        CHECK(state.nonce.has_value() == true);
        CHECK(state.nonce.value() == 10);

        CHECK(state.code.has_value() == true);
        CHECK(state.code.value() == silkworm::from_hex("0xdaa6d5560000000000000000000000000000000000000000000000000000000000000000"));

        CHECK(state.state.empty());
        CHECK(state.state_diff.empty());
    }
    SECTION("Account overrides with states") {
        auto json = R"({
            "state": {
                "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": "0x1000000"
            },
            "stateDiff": {
                "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6": "0x1000000"
            }
        })"_json;

        auto state = json.get<AccountOverrides>();

        CHECK(state.balance.has_value() == false);
        CHECK(state.nonce.has_value() == false);
        CHECK(state.code.has_value() == false);

        CHECK(state.state.size() == 1);
        CHECK(state.state[0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32] == intx::uint256{16777216});

        CHECK(state.state_diff.size() == 1);
        CHECK(state.state_diff[0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32] == intx::uint256{16777216});
    }
}

TEST_CASE("SimulationContext", "[silkworm::json][from_json]") {
    SECTION("Only block number") {
        auto json = R"({
            "blockNumber": 1000
        })"_json;

        auto context = json.get<SimulationContext>();
        CHECK(context.block_num.is_number());
        CHECK(context.block_num.number() == 1000);
        CHECK(context.transaction_index == -1);
    }
    SECTION("Block number and tx index") {
        auto json = R"({
            "blockNumber": 1000,
            "transactionIndex": 5
        })"_json;

        auto context = json.get<SimulationContext>();
        CHECK(context.block_num.is_number());
        CHECK(context.block_num.number() == 1000);
        CHECK(context.transaction_index == 5);
    }
}
}  // namespace silkworm::rpc
