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

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/json/types.hpp>

#include "filter.hpp"

namespace silkworm::rpc {

using Catch::Matchers::Message;
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
}

}  // namespace silkworm::rpc
