/*
   Copyright 2021 The Silkworm Authors

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

#include <catch2/catch.hpp>

#include "protocol_param.hpp"

namespace silkworm {

TEST_CASE("EIP-2930 intrinsic gas") {
    std::vector<AccessListEntry> access_list{
        {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
         {
             0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
             0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
         }},
        {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
    };

    Transaction txn{
        Transaction::Type::kEip2930,                         // type
        7,                                                   // nonce
        30000000000,                                         // max_priority_fee_per_gas
        30000000000,                                         // max_fee_per_gas
        5748100,                                             // gas_limit
        0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,  // to
        2 * kEther,                                          // value
        {},                                                  // data
        false,                                               // odd_y_parity
        5,                                                   // chain_id
        intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
        intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
        access_list,
    };

    intx::uint128 g0{intrinsic_gas(txn, /*homestead=*/true, /*istanbul=*/true)};
    CHECK(g0 == fee::kGTransaction + 2 * fee::kAccessListAddressCost + 2 * fee::kAccessListStorageKeyCost);
}

}  // namespace silkworm
