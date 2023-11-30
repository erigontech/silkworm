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

#include "merge_rule_set.hpp"

#include <optional>
#include <utility>

#include <silkworm/core/common/assert.hpp>

#include "param.hpp"

namespace silkworm::protocol {

MergeRuleSet::MergeRuleSet(RuleSetPtr pre_merge_rule_set, const ChainConfig& chain_config)
    : BaseRuleSet{chain_config, /*prohibit_ommers=*/true},
      terminal_total_difficulty_{*chain_config.terminal_total_difficulty},
      pre_merge_rule_set_{std::move(pre_merge_rule_set)} {}

ValidationResult MergeRuleSet::pre_validate_block_body(const Block& block, const BlockState& state) {
    if (block.header.difficulty != 0) {
        return pre_merge_rule_set_->pre_validate_block_body(block, state);
    }
    return BaseRuleSet::pre_validate_block_body(block, state);
}

ValidationResult MergeRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                     bool with_future_timestamp_check) {
    // TODO(yperbasis) how will all this work with backwards sync?

    const std::optional<BlockHeader> parent{BaseRuleSet::get_parent_header(state, header)};
    if (!parent) {
        return ValidationResult::kUnknownParent;
    }

    const std::optional<intx::uint256> parent_total_difficulty{
        state.total_difficulty(parent->number, header.parent_hash)};
    if (!parent_total_difficulty) {
        return ValidationResult::kUnknownParentTotalDifficulty;
    }
    const bool ttd_reached{parent_total_difficulty >= terminal_total_difficulty_};

    if (header.difficulty != 0) {
        if (ttd_reached) {
            return ValidationResult::kPoWBlockAfterMerge;
        }
        return pre_merge_rule_set_->validate_block_header(header, state, with_future_timestamp_check);
    }

    // PoS block
    if (!ttd_reached) {
        return ValidationResult::kPoSBlockBeforeMerge;
    }
    return BaseRuleSet::validate_block_header(header, state, with_future_timestamp_check);
}

ValidationResult MergeRuleSet::validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader&) {
    SILKWORM_ASSERT(header.difficulty == 0);
    return header.nonce == BlockHeader::NonceType{} ? ValidationResult::kOk : ValidationResult::kInvalidNonce;
}

void MergeRuleSet::initialize(EVM& evm) {
    const BlockHeader& header{evm.block().header};
    if (header.difficulty != 0) {
        pre_merge_rule_set_->initialize(evm);
        return;
    }

    if (evm.revision() < EVMC_CANCUN) {
        return;
    }

    // EIP-4788: Beacon block root in the EVM
    SILKWORM_ASSERT(header.parent_beacon_block_root);
    Transaction system_txn(TransactionType::kSystem, kBeaconRootsAddress, Bytes{ByteView{*header.parent_beacon_block_root}});
    system_txn.from = kSystemAddress;
    evm.execute(system_txn, kSystemCallGasLimit);
}

void MergeRuleSet::finalize(IntraBlockState& state, const Block& block) {
    if (block.header.difficulty != 0) {
        pre_merge_rule_set_->finalize(state, block);
        return;
    }

    if (!block.withdrawals) {
        return;
    }

    // See EIP-4895: Beacon chain push withdrawals as operations
    for (const Withdrawal& w : *block.withdrawals) {
        const auto amount_in_wei{intx::uint256{w.amount} * intx::uint256{kGiga}};
        state.add_to_balance(w.address, amount_in_wei);
    }
}

evmc::address MergeRuleSet::get_beneficiary(const BlockHeader& header) {
    if (header.difficulty != 0) {
        return pre_merge_rule_set_->get_beneficiary(header);
    }
    return BaseRuleSet::get_beneficiary(header);
}

ValidationResult MergeRuleSet::validate_ommers(const Block& block, const BlockState& state) {
    if (block.header.difficulty != 0) {
        return pre_merge_rule_set_->validate_ommers(block, state);
    }
    return BaseRuleSet::validate_ommers(block, state);
}

BlockReward MergeRuleSet::compute_reward(const Block& block) {
    if (block.header.difficulty != 0) {
        return pre_merge_rule_set_->compute_reward(block);
    }
    return BaseRuleSet::compute_reward(block);
}

}  // namespace silkworm::protocol
