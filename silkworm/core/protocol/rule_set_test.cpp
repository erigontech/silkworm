// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rule_set.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/protocol/param.hpp>

namespace silkworm::protocol {

TEST_CASE("Rule Set factory") {
    RuleSetPtr rule_set;
    rule_set = rule_set_factory(kMainnetConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(kHoleskyConfig);  // Merged from genesis
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(kSepoliaConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(test::kLondonConfig);  // No-proof rule set
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 2000000000000000000);
    rule_set = rule_set_factory(ChainConfig{.rule_set_config = bor::Config{}});
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(ChainConfig{.rule_set_config = NoPreMergeConfig{}});
    CHECK(!rule_set);
}

}  // namespace silkworm::protocol
