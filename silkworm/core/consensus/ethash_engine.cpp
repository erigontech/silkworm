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

#include "ethash_engine.hpp"

#include <silkworm/core/chain/protocol_param.hpp>
#include <silkworm/core/common/endian.hpp>

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
        const intx::uint256 ommer_reward{((8 + ommer.number - block_number) * block_reward) >> 3};
        state.add_to_balance(ommer.beneficiary, ommer_reward);
        miner_reward += block_reward >> 5;  // div 32
    }

    state.add_to_balance(block.header.beneficiary, miner_reward);
}

// Ethash ProofOfWork verification
ValidationResult EthashEngine::validate_seal(const BlockHeader& header) {
    const int epoch_number{static_cast<int>(header.number / ethash::epoch_length)};
    if (!epoch_context_ || epoch_context_->epoch_number != epoch_number) {
        epoch_context_.reset();  // Firstly release the obsoleted context
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

intx::uint256 EthashEngine::difficulty(const BlockHeader& header, const BlockHeader& parent) {
    const bool parent_has_uncles{parent.ommers_hash != kEmptyListHash};
    return difficulty(header.number, header.timestamp, parent.difficulty,
                      parent.timestamp, parent_has_uncles, chain_config_);
}

intx::uint256 EthashEngine::difficulty(uint64_t block_number, const uint64_t block_timestamp,
                                       const intx::uint256& parent_difficulty, const uint64_t parent_timestamp,
                                       const bool parent_has_uncles, const ChainConfig& config) {
    const evmc_revision rev{config.revision(block_number, block_timestamp)};

    intx::uint256 difficulty{parent_difficulty};

    const intx::uint256 x{parent_difficulty >> 11};  // parent_difficulty / 2048;

    if (rev >= EVMC_BYZANTIUM) {
        difficulty -= x * 99;

        // https://eips.ethereum.org/EIPS/eip-100
        const uint64_t y{parent_has_uncles ? 2u : 1u};
        const uint64_t z{(block_timestamp - parent_timestamp) / 9};
        if (99 + y > z) {
            difficulty += (99 + y - z) * x;
        }
    } else if (rev >= EVMC_HOMESTEAD) {
        difficulty -= x * 99;

        const uint64_t z{(block_timestamp - parent_timestamp) / 10};
        if (100 > z) {
            difficulty += (100 - z) * x;
        }
    } else {
        if (block_timestamp - parent_timestamp < 13) {
            difficulty += x;
        } else {
            difficulty -= x;
        }
    }

    uint64_t bomb_delay{0};
    if (config.gray_glacier_block.has_value() && block_number >= config.gray_glacier_block) {
        // https://eips.ethereum.org/EIPS/eip-5133
        bomb_delay = 11'400'000;
    } else if (config.arrow_glacier_block.has_value() && block_number >= config.arrow_glacier_block) {
        // https://eips.ethereum.org/EIPS/eip-4345
        bomb_delay = 10'700'000;
    } else if (rev >= EVMC_LONDON) {
        // https://eips.ethereum.org/EIPS/eip-3554
        bomb_delay = 9'700'000;
    } else if (config.muir_glacier_block.has_value() && block_number >= config.muir_glacier_block) {
        // https://eips.ethereum.org/EIPS/eip-2384
        bomb_delay = 9'000'000;
    } else if (rev >= EVMC_CONSTANTINOPLE) {
        // https://eips.ethereum.org/EIPS/eip-1234
        bomb_delay = 5'000'000;
    } else if (rev >= EVMC_BYZANTIUM) {
        // https://eips.ethereum.org/EIPS/eip-649
        bomb_delay = 3'000'000;
    }

    if (block_number > bomb_delay) {
        block_number -= bomb_delay;
    } else {
        block_number = 0;
    }

    const uint64_t n{block_number / 100'000};
    if (n >= 2) {
        static constexpr intx::uint256 one{1};
        difficulty += one << (n - 2);
    }

    static constexpr uint64_t kMinDifficulty{0x20000};
    if (difficulty < kMinDifficulty) {
        difficulty = kMinDifficulty;
    }
    return difficulty;
}

}  // namespace silkworm::consensus
