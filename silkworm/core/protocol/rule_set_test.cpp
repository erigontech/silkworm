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

#include "rule_set.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/protocol/param.hpp>

namespace silkworm::protocol {

TEST_CASE("Rule Set factory") {
    RuleSetPtr rule_set;
    BlockHeader nonzero_difficulty_header {
        .difficulty = intx::from_string<intx::uint256>("1"),
        // We need at least kExtraSealSize bytes in extra_data for beneficiary computation in Bor
        .extra_data = Bytes(kExtraSealSize, 0x0),
    };
    evmc::address empty_beneficiary{};

    rule_set = rule_set_factory(kMainnetConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) == empty_beneficiary);
    rule_set = rule_set_factory(kHoleskyConfig);  // Merged from genesis
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) == empty_beneficiary);
    rule_set = rule_set_factory(kSepoliaConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) == empty_beneficiary);
    rule_set = rule_set_factory(test::kLondonConfig);  // No-proof rule set
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) == empty_beneficiary);
    rule_set = rule_set_factory(kGoerliConfig);  // Clique rule set
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) == empty_beneficiary);
    rule_set = rule_set_factory(ChainConfig{.rule_set_config = bor::Config{}});
    CHECK(rule_set);
    CHECK(rule_set->get_beneficiary(nonzero_difficulty_header) != empty_beneficiary);
    rule_set = rule_set_factory(ChainConfig{.rule_set_config = NoPreMergeConfig{}});
    CHECK(!rule_set);
}

}  // namespace silkworm::protocol
