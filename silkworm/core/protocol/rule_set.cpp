// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rule_set.hpp"

#include <algorithm>
#include <sstream>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/overloaded.hpp>

#include "bor_rule_set.hpp"
#include "ethash_rule_set.hpp"
#include "merge_rule_set.hpp"
#include "param.hpp"

namespace silkworm::protocol {

ValidationResult RuleSet::pre_validate_block_body(const Block& block, const BlockState& state) {
    const BlockHeader& header{block.header};
    const evmc_revision rev{chain_config_->revision(header.number, header.timestamp)};

    const evmc::bytes32 txn_root{compute_transaction_root(block)};
    if (txn_root != header.transactions_root) {
        return ValidationResult::kWrongTransactionsRoot;
    }

    if (ValidationResult err{pre_validate_transactions(block, *chain_config_)}; err != ValidationResult::kOk) {
        return err;
    }

    if (chain_config_->withdrawals_activated(header.timestamp)) {
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
        const auto max_blob_gas_per_block = rev >= EVMC_PRAGUE ? kMaxBlobGasPerBlockPrague : kMaxBlobGasPerBlock;
        if (blob_gas_used > max_blob_gas_per_block) {
            return ValidationResult::kTooManyBlobs;
        }
    }
    if (header.blob_gas_used != blob_gas_used) {
        return ValidationResult::kWrongBlobGasUsed;
    }

    if (block.ommers.empty()) {
        return header.ommers_hash == kEmptyListHash ? ValidationResult::kOk : ValidationResult::kWrongOmmersHash;
    }
    if (prohibit_ommers_) {
        return ValidationResult::kTooManyOmmers;
    }

    const evmc::bytes32 ommers_hash{compute_ommers_hash(block)};
    if (ByteView{ommers_hash.bytes} != ByteView{header.ommers_hash}) {
        return ValidationResult::kWrongOmmersHash;
    }

    return validate_ommers(block, state);
}

ValidationResult RuleSet::validate_ommers(const Block& block, const BlockState& state) {
    if (prohibit_ommers_) {
        return block.ommers.empty() ? ValidationResult::kOk : ValidationResult::kTooManyOmmers;
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

ValidationResult RuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
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
    if (header.number == chain_config_->london_block) {
        parent_gas_limit = parent->gas_limit * kElasticityMultiplier;  // EIP-1559
    }

    const uint64_t gas_delta{header.gas_limit > parent_gas_limit ? header.gas_limit - parent_gas_limit
                                                                 : parent_gas_limit - header.gas_limit};
    if (gas_delta >= parent_gas_limit / 1024) {
        return ValidationResult::kInvalidGasLimit;
    }

    const evmc_revision rev{chain_config_->revision(header.number, header.timestamp)};

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

    if (chain_config_->withdrawals_activated(header.timestamp)) {
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
        if (header.excess_blob_gas != calc_excess_blob_gas(*parent, rev)) {
            return ValidationResult::kWrongExcessBlobGas;
        }
    }

    if (rev < EVMC_PRAGUE) {
        if (header.requests_hash) {
            return ValidationResult::kFieldBeforeFork;
        }
    }

    return validate_difficulty_and_seal(header, *parent);
}

ValidationResult RuleSet::validate_extra_data(const BlockHeader& header) const {
    if (header.extra_data.size() > kMaxExtraDataBytes) {
        return ValidationResult::kExtraDataTooLong;
    }
    return ValidationResult::kOk;
}

std::optional<BlockHeader> RuleSet::get_parent_header(const BlockState& state, const BlockHeader& header) {
    if (header.number == 0) {
        return std::nullopt;
    }
    return state.read_header(header.number - 1, header.parent_hash);
}

bool RuleSet::is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
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

evmc::address RuleSet::get_beneficiary(const BlockHeader& header) { return header.beneficiary; }

BlockReward RuleSet::compute_reward(const Block&) {
    return {0, {}};
}

void RuleSet::add_fee_transfer_log(IntraBlockState&, const intx::uint256&, const evmc::address&,
                                   const intx::uint256&, const evmc::address&, const intx::uint256&) {
    // do nothing by default
}

static RuleSetPtr pre_merge_rule_set(const ChainConfig& chain_config) {
    return std::visit<RuleSetPtr>(
        Overloaded{
            [&](const NoPreMergeConfig&) { return nullptr; },
            [&](const EthashConfig&) { return std::make_unique<EthashRuleSet>(chain_config); },
            [&](const bor::Config&) { return std::make_unique<BorRuleSet>(chain_config); },
        },
        chain_config.rule_set_config);
}

RuleSetPtr rule_set_factory(const ChainConfig& chain_config) {
    SILKWORM_ASSERT(chain_config.valid_pre_merge_config());

    RuleSetPtr rule_set{pre_merge_rule_set(chain_config)};
    if (chain_config.terminal_total_difficulty) {
        rule_set = std::make_unique<MergeRuleSet>(std::move(rule_set), chain_config);
    }
    return rule_set;
}

std::ostream& operator<<(std::ostream& out, const BlockReward& reward) {
    out << reward.to_string();
    return out;
}

std::string BlockReward::to_string() const {
    const auto& reward = *this;
    std::stringstream out;

    out << "miner_reward: " << intx::to_string(reward.miner) << " ommer_rewards: [";
    for (size_t i{0}; i < reward.ommers.size(); ++i) {
        out << intx::to_string(reward.ommers[i]);
        if (i != reward.ommers.size() - 1) {
            out << " ";
        }
    }
    out << "]";
    return out.str();
}

}  // namespace silkworm::protocol
