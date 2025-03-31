// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ethash_rule_set.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::protocol {

TEST_CASE("DifficultyTest34") {
    uint64_t block_num{0x33e140};
    uint64_t block_timestamp{0x04bdbdaf};
    uint64_t parent_difficulty{0x7268db7b46b0b154};
    uint64_t parent_timestamp{0x04bdbdaf};
    bool parent_has_uncles{false};

    intx::uint256 difficulty{EthashRuleSet::difficulty(block_num, block_timestamp, parent_difficulty, parent_timestamp,
                                                       parent_has_uncles, kMainnetConfig)};
    CHECK(difficulty == 0x72772897b619876a);
}

}  // namespace silkworm::protocol
