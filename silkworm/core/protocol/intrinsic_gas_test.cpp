/*
   Copyright 2022 The Silkworm Authors

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

#include "intrinsic_gas.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/config.hpp>

#include "param.hpp"

namespace silkworm {

TEST_CASE("num_words") {
    CHECK(num_words(0) == 0);
    CHECK(num_words(1) == 1);
    CHECK(num_words(31) == 1);
    CHECK(num_words(32) == 1);
    CHECK(num_words(33) == 2);
    CHECK(num_words(0xFFFFFFFFFFFFFFDF) == 0x7FFFFFFFFFFFFFF);
    CHECK(num_words(0xFFFFFFFFFFFFFFE0) == 0x7FFFFFFFFFFFFFF);
    CHECK(num_words(0xFFFFFFFFFFFFFFE1) == 0x800000000000000);
    CHECK(num_words(0xFFFFFFFFFFFFFFFE) == 0x800000000000000);
    CHECK(num_words(0xFFFFFFFFFFFFFFFF) == 0x800000000000000);
}

namespace protocol {

    TEST_CASE("EIP-2930 intrinsic gas") {
        std::vector<AccessListEntry> access_list{
            {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
             {
                 0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
                 0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
             }},
            {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
        };

        UnsignedTransaction txn{
            .type = TransactionType::kAccessList,
            .chain_id = kSepoliaConfig.chain_id,
            .nonce = 7,
            .max_priority_fee_per_gas = 30000000000,
            .max_fee_per_gas = 30000000000,
            .gas_limit = 5748100,
            .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
            .value = 2 * kEther,
            .access_list = access_list};

        intx::uint128 g0{intrinsic_gas(txn, EVMC_ISTANBUL)};
        CHECK(g0 == fee::kGTransaction + 2 * fee::kAccessListAddressCost + 2 * fee::kAccessListStorageKeyCost);
    }

    TEST_CASE("EIP-7623 intrinsic gas") {
        // EIP-7623 rules should take precedence

        const Bytes calldata = Bytes(22 * 1024, 1);
        UnsignedTransaction txn{
            .type = TransactionType::kDynamicFee,
            .chain_id = kSepoliaConfig.chain_id,
            .nonce = 7,
            .max_priority_fee_per_gas = 30000000000,
            .max_fee_per_gas = 30000000000,
            .gas_limit = 25748100,
            .data = calldata,
            .value = 2 * kEther};

        intx::uint128 g0{intrinsic_gas(txn, EVMC_PRAGUE)};
        // Calldata contains only 'ones' and the cost per EIP-7623 is higher
        CHECK(g0 == fee::kGTransaction + 4 * calldata.size() * fee::kTotalCostFloorPerToken);
    }

}  // namespace protocol

}  // namespace silkworm
