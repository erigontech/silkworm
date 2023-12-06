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

#include "base_rule_set.hpp"

#include <algorithm>

#include <silkworm/core/common/empty_hashes.hpp>

#include "param.hpp"

namespace silkworm::protocol {

ValidationResult BaseRuleSet::pre_validate_block_body(const Block& block, const BlockState& state) {
    const BlockHeader& header{block.header};
    const evmc_revision rev{chain_config_.revision(header.number, header.timestamp)};

    const evmc::bytes32 txn_root{compute_transaction_root(block)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    if (ValidationResult err{pre_validate_transactions(block, chain_config_)}; err != ValidationResult::kOk) {
        return err;
    }

    if (chain_config_.withdrawals_activated(header.timestamp)) {
        if (!block.withdrawals) {
            return ValidationResult::kMissingField;
        }
    } else {
        if (block.withdrawals) {
            return ValidationResult::kFieldBeforeFork;
        }
    }

    const std::optional<evmc::bytes32> withdrawals_root{compute_withdrawals_root(block)};
    if (withdrawals_root != header.withdrawals_root) {
        return ValidationResult::kWrongWithdrawalsRoot;
    }

    std::optional<uint64_t> blob_gas_used{std::nullopt};
    if (rev >= EVMC_CANCUN) {
        blob_gas_used = 0;
        for (const Transaction& tx : block.transactions) {
            *blob_gas_used += tx.total_blob_gas();
        }
        if (blob_gas_used > kMaxBlobGasPerBlock) {
            return ValidationResult::kTooManyBlobs;
        }
    }
    if (header.blob_gas_used != blob_gas_used) {
        return ValidationResult::kWrongBlobGasUsed;
    }

    if (block.ommers.empty()) {
        return header.ommers_hash == kEmptyListHash ? ValidationResult::kOk : ValidationResult::kWrongOmmersHash;
    } else if (prohibit_ommers_) {
        return ValidationResult::kTooManyOmmers;
    }

    const evmc::bytes32 ommers_hash{compute_ommers_hash(block)};
    if (ByteView{ommers_hash.bytes} != ByteView{header.ommers_hash}) {
        return ValidationResult::kWrongOmmersHash;
    }

    return validate_ommers(block, state);
}

ValidationResult BaseRuleSet::validate_ommers(const Block& block, const BlockState& state) {
    if (prohibit_ommers_) {
        if (block.ommers.empty()) {
            return ValidationResult::kOk;
        } else {
            return ValidationResult::kTooManyOmmers;
        }
    }

    if (block.ommers.size() > 2) {
        return ValidationResult::kTooManyOmmers;
    }

    if (block.ommers.size() == 2 && block.ommers[0] == block.ommers[1]) {
        return ValidationResult::kDuplicateOmmer;
    }

    const BlockHeader& header{block.header};
    const std::optional<BlockHeader> parent{get_parent_header(state, header)};

    for (const BlockHeader& ommer : block.ommers) {
        if (ValidationResult err{validate_block_header(ommer, state, /*with_future_timestamp_check=*/false)};
            err != ValidationResult::kOk) {
            return ValidationResult::kInvalidOmmerHeader;
        }
        std::vector<BlockHeader> old_ommers;
        if (!is_kin(ommer, *parent, header.parent_hash, 6, state, old_ommers)) {
            return ValidationResult::kNotAnOmmer;
        }

        if (std::ranges::find(old_ommers, ommer) != old_ommers.end()) {
            return ValidationResult::kDuplicateOmmer;
        }
    }

    return ValidationResult::kOk;
}

ValidationResult BaseRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                    bool with_future_timestamp_check) {
    if (with_future_timestamp_check) {
        const std::time_t now{std::time(nullptr)};
        if (header.timestamp > static_cast<uint64_t>(now)) {
            return ValidationResult::kFutureBlock;
        }
    }

    if (header.gas_used > header.gas_limit) {
        return ValidationResult::kGasAboveLimit;
    }

    if (header.gas_limit < kMinGasLimit || header.gas_limit > kMaxGasLimit) {
        return ValidationResult::kInvalidGasLimit;
    }

    if (ValidationResult res{validate_extra_data(header)}; res != ValidationResult::kOk) {
        return res;
    }

    if (prohibit_ommers_ && header.ommers_hash != kEmptyListHash) {
        return ValidationResult::kWrongOmmersHash;
    }

    const std::optional<BlockHeader> parent{get_parent_header(state, header)};
    if (!parent.has_value()) {
        return ValidationResult::kUnknownParent;
    }

    if (header.timestamp <= parent->timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    uint64_t parent_gas_limit{parent->gas_limit};
    if (header.number == chain_config_.london_block) {
        parent_gas_limit = parent->gas_limit * kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    const evmc_revision rev{chain_config_.revision(header.number, header.timestamp)};

    if (rev < EVMC_LONDON) {
        if (header.base_fee_per_gas) {
            return ValidationResult::kFieldBeforeFork;
        }
    } else {
        if (!header.base_fee_per_gas) {
            return ValidationResult::kMissingField;
        }
        if (header.base_fee_per_gas != expected_base_fee_per_gas(*parent)) {
            return ValidationResult::kWrongBaseFee;
        }
    }

    if (chain_config_.withdrawals_activated(header.timestamp)) {
        if (!header.withdrawals_root) {
            return ValidationResult::kMissingField;
        }
    } else {
        if (header.withdrawals_root) {
            return ValidationResult::kFieldBeforeFork;
        }
    }

    if (rev < EVMC_CANCUN) {
        if (header.blob_gas_used || header.excess_blob_gas || header.parent_beacon_block_root) {
            return ValidationResult::kFieldBeforeFork;
        }
    } else {
        if (!header.blob_gas_used || !header.excess_blob_gas || !header.parent_beacon_block_root) {
            return ValidationResult::kMissingField;
        }
        if (header.excess_blob_gas != calc_excess_blob_gas(*parent)) {
            return ValidationResult::kWrongExcessBlobGas;
        }
    }

    return validate_difficulty_and_seal(header, *parent);
}

ValidationResult BaseRuleSet::validate_extra_data(const BlockHeader& header) const {
    if (header.extra_data.length() > kMaxExtraDataBytes) {
        return ValidationResult::kExtraDataTooLong;
    }
    return ValidationResult::kOk;
}

std::optional<BlockHeader> BaseRuleSet::get_parent_header(const BlockState& state, const BlockHeader& header) {
    if (header.number == 0) {
        return std::nullopt;
    }
    return state.read_header(header.number - 1, header.parent_hash);
}

bool BaseRuleSet::is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                         const evmc::bytes32& mainline_hash, unsigned int n, const BlockState& state,
                         std::vector<BlockHeader>& old_ommers) {
    if (n == 0 || branch_header == mainline_header) {
        return false;
    }

    BlockBody mainline_body;
    if (!state.read_body(mainline_header.number, mainline_hash, mainline_body)) {
        return false;
    }

    old_ommers.insert(old_ommers.end(), mainline_body.ommers.begin(), mainline_body.ommers.end());

    std::optional<BlockHeader> mainline_parent{get_parent_header(state, mainline_header)};
    if (!mainline_parent) {
        return false;
    }

    std::optional<BlockHeader> branch_parent{get_parent_header(state, branch_header)};
    if (branch_parent == mainline_parent) {
        return true;
    }

    return is_kin(branch_header, mainline_parent.value(), mainline_header.parent_hash, n - 1, state, old_ommers);
}

evmc::address BaseRuleSet::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

BlockReward BaseRuleSet::compute_reward(const Block&) {
    return {0, {}};
}

}  // namespace silkworm::protocol
