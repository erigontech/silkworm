// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <optional>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("empty call", "[rpc][types][call]") {
    Call call{};
    CHECK(call.from == std::nullopt);
    CHECK(call.to == std::nullopt);
    CHECK(call.gas == std::nullopt);
    CHECK(call.gas_price == std::nullopt);
    CHECK(call.max_priority_fee_per_gas == std::nullopt);
    CHECK(call.max_fee_per_gas == std::nullopt);
    CHECK(call.value == std::nullopt);
    CHECK(call.data == std::nullopt);
    CHECK(call.nonce == std::nullopt);
    CHECK(call.access_list.empty());
}

TEST_CASE("call with gas price", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        21000,         // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        {},
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 21000);
    CHECK(txn.max_priority_fee_per_gas == 21000);
    CHECK(txn.nonce == 1);
}

TEST_CASE("call w/o gas price and max_fee_per_gas & max_priority_fee_per_gas not zero", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        std::nullopt,  // gas_price
        18000,         // max_priority_fee_per_gas
        18000,         // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        {},
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 18000);
    CHECK(txn.max_priority_fee_per_gas == 18000);
    CHECK(txn.nonce == 1);
}

TEST_CASE("call w/o gas price, max_fee_per_gas & max_priority_fee_per_gas", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        std::nullopt,  // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        {},
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 0);
    CHECK(txn.max_priority_fee_per_gas == 0);
    CHECK(txn.nonce == 1);
}

TEST_CASE("call w/o gas price with base_fee", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        std::nullopt,  // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        {},
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 0);
    CHECK(txn.max_priority_fee_per_gas == 0);
    CHECK(txn.nonce == 1);
}

TEST_CASE("call with gas price and base_fee", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        21000,         // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        {},
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 21000);
    CHECK(txn.max_priority_fee_per_gas == 21000);
    CHECK(txn.nonce == 1);
}

AccessList access_list{
    {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
     {
         0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
         0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
     }},
    {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
};

TEST_CASE("call with no gas price and no max_fee_per_gas and max_priority_fee_per_gas", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,  // gas
        0,    // gas_price
        std::nullopt,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        23,
    };
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 0);
    CHECK(txn.nonce == 23);
    CHECK(txn.max_priority_fee_per_gas == 0);
}

TEST_CASE("call with no gas price and valid max_fee_per_gas and max_priority_fee_per_gas", "[rpc][types][call]") {
    Call call{
        0x99f9b87991262f6ba471f09758cde1c0fc1de734_address,  // from
        0x5df9b87991262f6ba471f09758cde1c0fc1de734_address,  // to
        235,                                                 // gas
        std::nullopt,                                        // gas_price
        10000,                                               // max_fee_per_gas
        10000,                                               // max_priority_fee_per_gas
        31337,                                               // value
        silkworm::from_hex("001122aabbcc")};
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.sender() == 0x99f9b87991262f6ba471f09758cde1c0fc1de734_address);
    CHECK(txn.to == 0x5df9b87991262f6ba471f09758cde1c0fc1de734_address);
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 10000);
    CHECK(txn.max_priority_fee_per_gas == 10000);
    CHECK(txn.value == 31337);
    CHECK(txn.data == silkworm::from_hex("001122aabbcc"));
}

TEST_CASE("call with no gas", "[rpc][types][call]") {
    Call call;
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 50000000);
    CHECK(txn.value == 0);
    CHECK(txn.data.empty());
}

TEST_CASE("call with AccessList", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        21000,         // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1,             // nonce
        access_list};
    silkworm::Transaction txn = call.to_transaction();
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 21000);
    CHECK(txn.max_priority_fee_per_gas == 21000);
    CHECK(txn.nonce == 1);
    CHECK(!txn.access_list.empty());
    CHECK(txn.access_list == access_list);
}

TEST_CASE("call with no AccessList and pass it to_transaction", "[rpc][types][call]") {
    Call call{
        std::nullopt,
        std::nullopt,
        235,           // gas
        21000,         // gas_price
        std::nullopt,  // max_priority_fee_per_gas
        std::nullopt,  // max_fee_per_gas
        31337,         // value
        {},            // data
        1};            // nonce
    silkworm::Transaction txn = call.to_transaction(access_list);
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 21000);
    CHECK(txn.max_priority_fee_per_gas == 21000);
    CHECK(txn.nonce == 1);
    CHECK(!txn.access_list.empty());
    CHECK(txn.access_list == access_list);
}

TEST_CASE("call with no nonce and pass it to_transaction", "[rpc][types][call]") {
    uint64_t nonce = 5;
    Call call{
        std::nullopt,
        std::nullopt,
        235,            // gas
        21000,          // gas_price
        std::nullopt,   // max_priority_fee_per_gas
        std::nullopt,   // max_fee_per_gas
        31337,          // value
        {},             // data
        std::nullopt};  // nonce
    silkworm::Transaction txn = call.to_transaction(std::nullopt, nonce);
    CHECK(txn.gas_limit == 235);
    CHECK(txn.max_fee_per_gas == 21000);
    CHECK(txn.max_priority_fee_per_gas == 21000);
    CHECK(txn.nonce == nonce);
    CHECK(txn.access_list.empty());
}

}  // namespace silkworm::rpc
