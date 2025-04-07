// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <stdexcept>
#include <vector>

#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>

namespace silkworm::rpc {

struct Forks {
    evmc::bytes32 genesis_hash;
    std::vector<BlockNum> block_nums;
    std::vector<uint64_t> block_times;

    explicit Forks(const ChainConfig& cc) : genesis_hash(cc.genesis_hash.value_or(evmc::bytes32{})) {
        for (auto& fork_block_num : cc.distinct_fork_block_nums()) {
            if (fork_block_num) {  // Skip any forks in block 0, that's the genesis ruleset
                block_nums.push_back(fork_block_num);
            }
        }
        for (auto& fork_block_time : cc.distinct_fork_times()) {
            if (fork_block_time) {  // Skip any forks in block 0, that's the genesis ruleset
                block_times.push_back(fork_block_time);
            }
        }
    }
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& chain_config);

}  // namespace silkworm::rpc
