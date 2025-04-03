// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ethash_rule_set.hpp"

#include <silkworm/core/chain/dao.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/endian.hpp>

#include "param.hpp"

namespace silkworm::protocol {

// Ethash ProofOfWork verification
ValidationResult EthashRuleSet::validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) {
    const bool parent_has_uncles{parent.ommers_hash != kEmptyListHash};
    if (header.difficulty != difficulty(header.number, header.timestamp, parent.difficulty,
                                        parent.timestamp, parent_has_uncles, *chain_config_)) {
        return ValidationResult::kWrongDifficulty;
    }

    if (!std::get<EthashConfig>(chain_config_->rule_set_config).validate_seal) {
        return ValidationResult::kOk;
    }

    const int epoch_number{static_cast<int>(header.number / ethash::epoch_length)};
    if (!epoch_context_ || epoch_context_->epoch_number != epoch_number) {
        epoch_context_.reset();  // Firstly release the obsoleted context
        epoch_context_ = ethash::create_epoch_context(epoch_number);
    }

    const auto nonce{endian::load_big_u64(header.nonce.data())};
    const auto seal_hash(header.hash(/*for_sealing =*/true));
    const auto diff256{intx::be::store<ethash::hash256>(header.difficulty)};
    const auto sealh256{ethash::hash256_from_bytes(seal_hash.bytes)};
    const auto mixh256{ethash::hash256_from_bytes(header.prev_randao.bytes)};

    const auto ec{ethash::verify_against_difficulty(*epoch_context_, sealh256, mixh256, nonce, diff256)};
    return ec ? ValidationResult::kInvalidSeal : ValidationResult::kOk;
}

ValidationResult EthashRuleSet::validate_extra_data(const BlockHeader& header) const {
    // EIP-779: Hardfork Meta: DAO Fork
    if (chain_config_->dao_block && chain_config_->dao_block <= header.number &&
        header.number <= *(chain_config_->dao_block) + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    return RuleSet::validate_extra_data(header);
}

void EthashRuleSet::initialize(EVM& evm) {
    if (evm.block().header.number == evm.config().dao_block) {
        transfer_dao_balances(evm.state());
    }
}

ValidationResult EthashRuleSet::finalize(IntraBlockState& state, const Block& block, EVM&, const std::vector<Log>&) {
    const BlockReward reward{compute_reward(block)};
    state.add_to_balance(get_beneficiary(block.header), reward.miner);
    for (size_t i{0}; i < block.ommers.size(); ++i) {
        state.add_to_balance(block.ommers[i].beneficiary, reward.ommers[i]);
    }
    return ValidationResult::kOk;
}

static intx::uint256 block_reward_base(const evmc_revision rev) {
    if (rev >= EVMC_CONSTANTINOPLE) {
        return kBlockRewardConstantinople;
    }
    if (rev >= EVMC_BYZANTIUM) {
        return kBlockRewardByzantium;
    }
    return kBlockRewardFrontier;
}

BlockReward EthashRuleSet::compute_reward(const Block& block) {
    const BlockNum block_num = block.header.number;
    const evmc_revision rev{chain_config_->revision(block_num, block.header.timestamp)};
    const intx::uint256 base{block_reward_base(rev)};

    intx::uint256 miner_reward{base};
    std::vector<intx::uint256> ommer_rewards;
    ommer_rewards.reserve(block.ommers.size());
    // Accumulate the rewards for the miner and any included uncles
    for (const BlockHeader& ommer : block.ommers) {
        const intx::uint256 ommer_reward{((8 + ommer.number - block_num) * base) >> 3};
        ommer_rewards.push_back(ommer_reward);
        miner_reward += base >> 5;  // div 32
    }

    return {miner_reward, ommer_rewards};
}

intx::uint256 EthashRuleSet::difficulty(
    uint64_t block_num,
    const uint64_t block_timestamp,
    const intx::uint256& parent_difficulty,
    const uint64_t parent_timestamp,
    const bool parent_has_uncles,
    const ChainConfig& config) {
    const evmc_revision rev = config.revision(block_num, block_timestamp);

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
    if (config.gray_glacier_block.has_value() && block_num >= config.gray_glacier_block) {
        // EIP-5133: Delaying Difficulty Bomb to mid-September 2022
        bomb_delay = 11'400'000;
    } else if (config.arrow_glacier_block.has_value() && block_num >= config.arrow_glacier_block) {
        // EIP-4345: Difficulty Bomb Delay to June 2022
        bomb_delay = 10'700'000;
    } else if (rev >= EVMC_LONDON) {
        // EIP-3554: Difficulty Bomb Delay to December 2021
        bomb_delay = 9'700'000;
    } else if (config.muir_glacier_block.has_value() && block_num >= config.muir_glacier_block) {
        // EIP-2384: Muir Glacier Difficulty Bomb Delay
        bomb_delay = 9'000'000;
    } else if (rev >= EVMC_CONSTANTINOPLE) {
        // EIP-1234: Constantinople Difficulty Bomb Delay and Block Reward Adjustment
        bomb_delay = 5'000'000;
    } else if (rev >= EVMC_BYZANTIUM) {
        // EIP-649: Metropolis Difficulty Bomb Delay and Block Reward Reduction
        bomb_delay = 3'000'000;
    }

    if (block_num > bomb_delay) {
        block_num -= bomb_delay;
    } else {
        block_num = 0;
    }

    const uint64_t n = block_num / 100'000;
    if (n >= 2) {
        static constexpr intx::uint256 kOne{1};
        difficulty += kOne << (n - 2);
    }

    static constexpr uint64_t kMinDifficulty{0x20000};
    if (difficulty < kMinDifficulty) {
        difficulty = kMinDifficulty;
    }
    return difficulty;
}

}  // namespace silkworm::protocol
