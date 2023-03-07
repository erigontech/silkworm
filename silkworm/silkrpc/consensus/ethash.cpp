/*
    Copyright 2020 The Silkrpc Authors

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

#include "ethash.hpp"

#include <silkworm/core/chain/protocol_param.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkrpc::ethash {

BlockReward compute_reward(const ChainConfig& config, const silkworm::Block& block) {
    const auto cc_optional = silkworm::ChainConfig::from_json(config.config);
    if (!cc_optional) {
        throw std::runtime_error("Invalid chain config");
    }
    const auto chain_config = cc_optional.value();
    const auto revision = chain_config.revision(block.header.number, /*block_time=*/0);
    BlockReward block_reward;
    block_reward.miner_reward = silkworm::param::kBlockRewardFrontier;
    if (revision > evmc_revision::EVMC_BYZANTIUM) {
        block_reward.miner_reward = silkworm::param::kBlockRewardByzantium;
    }
    if (revision > evmc_revision::EVMC_CONSTANTINOPLE) {
        block_reward.miner_reward = silkworm::param::kBlockRewardConstantinople;
    }

    // Accumulate the rewards for the miner and any included uncles
    intx::uint256 ommer_reward;
    const auto header_number = block.header.number;
    for (const auto& uncle : block.ommers) {
        ommer_reward = uncle.number + 8;
        ommer_reward -= header_number;
        ommer_reward *= block_reward.miner_reward;
        ommer_reward /= 8;
        block_reward.ommer_rewards.push_back(ommer_reward);

        ommer_reward = block_reward.miner_reward / 32;

        block_reward.miner_reward += ommer_reward;
    }

    return block_reward;
}

std::ostream& operator<<(std::ostream& out, const BlockReward& reward) {
    out << "miner_reward: " << intx::to_string(reward.miner_reward) << " ommer_rewards: [";
    for (auto i{0}; i < reward.ommer_rewards.size(); i++) {
        out << intx::to_string(reward.ommer_rewards[i]);
        if (i != reward.ommer_rewards.size() - 1) {
            out << " ";
        }
    }
    out << "]";
    return out;
}

} // namespace silkrpc::ethash
