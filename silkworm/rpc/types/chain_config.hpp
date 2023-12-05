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

struct ChainConfig {
    evmc::bytes32 genesis_hash;
    nlohmann::json config;
};

struct Forks {
    const evmc::bytes32& genesis_hash;
    std::vector<BlockNum> block_numbers;
    std::vector<uint64_t> block_times;

    explicit Forks(const ChainConfig& chain_config) : genesis_hash(chain_config.genesis_hash) {
        const auto cc{silkworm::ChainConfig::from_json(chain_config.config)};
        if (!cc) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Chain config missing"};
        }
        for (auto& fork_block_number : cc->distinct_fork_numbers()) {
            if (fork_block_number) {  // Skip any forks in block 0, that's the genesis ruleset
                block_numbers.push_back(fork_block_number);
            }
        }
        for (auto& fork_block_time : cc->distinct_fork_times()) {
            if (fork_block_time) {  // Skip any forks in block 0, that's the genesis ruleset
                block_times.push_back(fork_block_time);
            }
        }
    }
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& chain_config);

}  // namespace silkworm::rpc
