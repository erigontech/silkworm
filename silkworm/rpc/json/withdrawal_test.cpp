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

#include "withdrawal.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm {

using evmc::literals::operator""_address;

TEST_CASE("serialize WithdrawalV1", "[silkworm::json][to_json]") {
    Withdrawal withdrawal{
        .index = 6,
        .validator_index = 12,
        .address = 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b_address,
        .amount = 10'000};
    CHECK(nlohmann::json(withdrawal) == R"({
        "index":"0x6",
        "validatorIndex":"0xc",
        "address":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
        "amount":"0x2710"
    })"_json);
}

}  // namespace silkworm
