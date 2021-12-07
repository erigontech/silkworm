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

#include "engine.hpp"

#include <silkworm/chain/difficulty.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/endian.hpp>

namespace silkworm::consensus {

void EthashEngine::finalize(IntraBlockState& state, const Block& block, const evmc_revision revision) {
    intx::uint256 block_reward;
    if (revision >= EVMC_CONSTANTINOPLE) {
        block_reward = param::kBlockRewardConstantinople;
    } else if (revision >= EVMC_BYZANTIUM) {
        block_reward = param::kBlockRewardByzantium;
    } else {
        block_reward = param::kBlockRewardFrontier;
    }

    const uint64_t block_number{block.header.number};
    intx::uint256 miner_reward{block_reward};
    for (const BlockHeader& ommer : block.ommers) {
        intx::uint256 ommer_reward{((8 + ommer.number - block_number) * block_reward) >> 3};
        state.add_to_balance(ommer.beneficiary, ommer_reward);
        miner_reward += block_reward / 32;
    }

    state.add_to_balance(block.header.beneficiary, miner_reward);
}

// Ethash ProofOfWork verification
ValidationResult EthashEngine::validate_seal(const BlockHeader& header) {
    const int epoch_number{static_cast<int>(header.number / ethash::epoch_length)};
    if (!epoch_context_ || epoch_context_->epoch_number != epoch_number) {
        epoch_context_.reset(); // Firstly release the obsoleted context
        epoch_context_ = ethash::create_epoch_context(epoch_number);
    }

    const auto nonce{endian::load_big_u64(header.nonce.data())};
    const auto seal_hash(header.hash(/*for_sealing =*/true));
    const auto diff256{intx::be::store<ethash::hash256>(header.difficulty)};
    const auto sealh256{ethash::hash256_from_bytes(seal_hash.bytes)};
    const auto mixh256{ethash::hash256_from_bytes(header.mix_hash.bytes)};

    const auto ec{ethash::verify_against_difficulty(*epoch_context_, sealh256, mixh256, nonce, diff256)};
    return ec ? ValidationResult::kInvalidSeal : ValidationResult::kOk;
}

ValidationResult EthashEngine::validate_difficulty(const BlockHeader& header, const BlockHeader& parent) {
    const bool parent_has_uncles{parent.ommers_hash != kEmptyListHash};
    const intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent.difficulty,
                                                        parent.timestamp, parent_has_uncles, chain_config_)};
    return difficulty == header.difficulty ? ValidationResult::kOk : ValidationResult::kWrongDifficulty;
}

}  // namespace silkworm::consensus
