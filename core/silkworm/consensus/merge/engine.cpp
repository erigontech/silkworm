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

namespace silkworm::consensus {

MergeEngine::MergeEngine(const ChainConfig& chain_config)
    : terminal_total_difficulty_{*chain_config.terminal_total_difficulty},
      ethash_engine_{chain_config},
      pos_engine_{chain_config} {}

ValidationResult MergeEngine::pre_validate_block(const Block& block, const BlockState& state) {
    if (block.header.difficulty != 0) {
        return ethash_engine_.pre_validate_block(block, state);
    } else {
        return pos_engine_.pre_validate_block(block, state);
    }
}

ValidationResult MergeEngine::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                    bool with_future_timestamp_check) {
    // TODO (Andrew) how will all this work with backwards sync?

    const std::optional<BlockHeader> parent{EngineBase::get_parent_header(state, header)};
    if (!parent.has_value()) {
        return ValidationResult::kUnknownParent;
    }

    if (header.difficulty != 0) {
        const std::optional<intx::uint256> parent_total_difficulty{
            state.total_difficulty(parent->number, header.parent_hash)};
        if (parent_total_difficulty == std::nullopt) {
            return ValidationResult::kUnknownParentTotalDifficulty;
        }
        if (parent_total_difficulty >= terminal_total_difficulty_) {
            return ValidationResult::kPoWBlockAfterMerge;
        }
        return ethash_engine_.validate_block_header(header, state, with_future_timestamp_check);
    } else {
        if (parent->difficulty != 0 && !terminal_pow_block(*parent, state)) {
            return ValidationResult::kPoSBlockBeforeMerge;
        }
        return pos_engine_.validate_block_header(header, state, with_future_timestamp_check);
    }
}

bool MergeEngine::terminal_pow_block(const BlockHeader& header, const BlockState& state) const {
    if (header.difficulty == 0) {
        return false;  // PoS block
    }

    const std::optional<BlockHeader> parent{EngineBase::get_parent_header(state, header)};
    if (parent == std::nullopt) {
        return false;
    }

    const std::optional<intx::uint256> parent_total_difficulty{
        state.total_difficulty(parent->number, header.parent_hash)};
    if (parent_total_difficulty == std::nullopt) {
        // TODO (Andrew) should return kUnknownParentTotalDifficulty instead
        return false;
    }

    return parent_total_difficulty < terminal_total_difficulty_ &&
           *parent_total_difficulty + header.difficulty >= terminal_total_difficulty_;
}

ValidationResult MergeEngine::validate_seal(const BlockHeader& header) {
    if (header.difficulty != 0) {
        return ethash_engine_.validate_seal(header);
    } else {
        return pos_engine_.validate_seal(header);
    }
}

void MergeEngine::finalize(IntraBlockState& state, const Block& block, evmc_revision revision) {
    if (block.header.difficulty != 0) {
        ethash_engine_.finalize(state, block, revision);
    } else {
        pos_engine_.finalize(state, block, revision);
    }
}

evmc::address MergeEngine::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

}  // namespace silkworm::consensus
