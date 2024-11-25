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
        for (auto& fork_block_num : cc.distinct_fork_numbers()) {
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
