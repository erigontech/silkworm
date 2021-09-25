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
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/trie/vector_root.hpp>

namespace silkworm::consensus {

ValidationResult ConsensusEngineBase::validate_block(const silkworm::Block& block, silkworm::State& state) {
    const BlockHeader& header{block.header};

    if (ValidationResult err{validate_block_header(header, state)}; err != ValidationResult::kOk) {
        return err;
    }

    Bytes ommers_rlp;
    rlp::encode(ommers_rlp, block.ommers);
    ethash::hash256 ommers_hash{keccak256(ommers_rlp)};
    if (full_view(ommers_hash.bytes) != full_view(header.ommers_hash)) {
        return ValidationResult::kWrongOmmersHash;
    }

    static constexpr auto kEncoder = [](Bytes& to, const Transaction& txn) {
        rlp::encode(to, txn, /*for_signing=*/false, /*wrap_eip2718_into_array=*/false);
    };

    evmc::bytes32 txn_root{trie::root_hash(block.transactions, kEncoder)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    if (block.ommers.size() > 2) {
        return ValidationResult::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationResult::kDuplicateOmmer;
    }

    std::optional<BlockHeader> parent{get_parent_header(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationResult err{validate_block_header(ommer, state)}; err != ValidationResult::kOk) {
            return ValidationResult::kInvalidOmmerHeader;
        }
        std::vector<BlockHeader> old_ommers;
        if (!is_kin(ommer, *parent, header.parent_hash, 6, state, old_ommers)) {
            return ValidationResult::kNotAnOmmer;
        }
        for (const BlockHeader& oo : old_ommers) {
            if (oo == ommer) {
                return ValidationResult::kDuplicateOmmer;
            }
        }
    }

    for (const Transaction& txn : block.transactions) {
        ValidationResult err{pre_validate_transaction(txn, header.number, chain_config_, header.base_fee_per_gas)};
        if (err != ValidationResult::kOk) {
            return err;
        }
    }

    return ValidationResult::kOk;
}

ValidationResult ConsensusEngineBase::validate_block_header(const BlockHeader& header, State& state) {
    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < 5000) {
        return ValidationResult::kInvalidGasLimit;
    }

    // https://github.com/ethereum/go-ethereum/blob/v1.9.25/consensus/ethash/consensus.go#L267
    // https://eips.ethereum.org/EIPS/eip-1985
    if (header.gas_limit > INT64_MAX) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (header.extra_data.length() > 32) {
        return ValidationResult::kExtraDataTooLong;
    }

    const std::optional<BlockHeader> parent{get_parent_header(state, header)};
    if (!parent.has_value()) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t parent_gas_limit{parent->gas_limit};
    if (header.number == chain_config_.revision_block(EVMC_LONDON)) {
        parent_gas_limit = parent->gas_limit * param::kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    const bool parent_has_uncles{parent->ommers_hash != kEmptyListHash};
    const intx::uint256 difficulty{canonical_difficulty(header.number, header.timestamp, parent->difficulty,
                                                        parent->timestamp, parent_has_uncles, chain_config_)};
    if (difficulty != header.difficulty) {
        return ValidationResult::kWrongDifficulty;
    }

    // https://eips.ethereum.org/EIPS/eip-779
    if (chain_config_.dao_block.has_value() && chain_config_.dao_block.value() <= header.number &&
        header.number <= chain_config_.dao_block.value() + 9) {
        static const Bytes kDaoExtraData{*from_hex("0x64616f2d686172642d666f726b")};
        if (header.extra_data != kDaoExtraData) {
            return ValidationResult::kWrongDaoExtraData;
        }
    }

    if (header.base_fee_per_gas != expected_base_fee_per_gas(header, parent.value())) {
        return ValidationResult::kWrongBaseFee;
    }

    return validate_seal(header);
}

void ConsensusEngineBase::apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
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

std::optional<BlockHeader> ConsensusEngineBase::get_parent_header(const State& state, const BlockHeader& header) {
    if (header.number == 0) {
        return std::nullopt;
    }
    return state.read_header(header.number - 1, header.parent_hash);
}
bool ConsensusEngineBase::is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                                 const evmc::bytes32& mainline_hash, unsigned int n, const State& state,
                                 std::vector<BlockHeader>& old_ommers) {
    if (n == 0 || branch_header == mainline_header) {
        return false;
    }

    std::optional<BlockBody> mainline_body{state.read_body(mainline_header.number, mainline_hash)};
    if (!mainline_body) {
        return false;
    }

    old_ommers.insert(old_ommers.end(), mainline_body->ommers.begin(), mainline_body->ommers.end());

    std::optional<BlockHeader> mainline_parent{get_parent_header(state, mainline_header)};
    if (!mainline_parent) {
        return false;
    }

    std::optional<BlockHeader> branch_parent{get_parent_header(state, branch_header)};
    if (branch_parent == mainline_parent) {
        return true;
    }

    return is_kin(branch_header, *mainline_parent, mainline_header.parent_hash, n - 1, state, old_ommers);

}

evmc::address ConsensusEngineBase::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

std::optional<intx::uint256> ConsensusEngineBase::expected_base_fee_per_gas(const BlockHeader& header,
                                                                            const BlockHeader& parent) {
    if (chain_config_.revision(header.number) < EVMC_LONDON) {
        return std::nullopt;
    }

    if (header.number == chain_config_.revision_block(EVMC_LONDON)) {
        return param::kInitialBaseFee;
    }

    const uint64_t parent_gas_target{parent.gas_limit / param::kElasticityMultiplier};

    assert(parent.base_fee_per_gas.has_value());
    const intx::uint256 parent_base_fee_per_gas{*parent.base_fee_per_gas};

    if (parent.gas_used == parent_gas_target) {
        return parent_base_fee_per_gas;
    }

    if (parent.gas_used > parent_gas_target) {
        const intx::uint256 gas_used_delta{parent.gas_used - parent_gas_target};
        intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                             param::kBaseFeeMaxChangeDenominator};
        if (base_fee_per_gas_delta < 1) {
            base_fee_per_gas_delta = 1;
        }
        return parent_base_fee_per_gas + base_fee_per_gas_delta;
    } else {
        const intx::uint256 gas_used_delta{parent_gas_target - parent.gas_used};
        const intx::uint256 base_fee_per_gas_delta{parent_base_fee_per_gas * gas_used_delta / parent_gas_target /
                                                   param::kBaseFeeMaxChangeDenominator};
        if (parent_base_fee_per_gas > base_fee_per_gas_delta) {
            return parent_base_fee_per_gas - base_fee_per_gas_delta;
        } else {
            return 0;
        }
    }
}

}  // namespace silkworm::consensus
