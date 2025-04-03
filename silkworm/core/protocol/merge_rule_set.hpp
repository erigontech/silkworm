// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/protocol/rule_set.hpp>

namespace silkworm::protocol {

// Mainnet protocol rule set that can handle blocks before, during, and after the Merge.
// See EIP-3675: Upgrade consensus to Proof-of-Stake.
class MergeRuleSet : public RuleSet {
  public:
    explicit MergeRuleSet(RuleSetPtr pre_merge_rule_set, const ChainConfig& chain_config);

    ValidationResult pre_validate_block_body(const Block& block, const BlockState& state) override;

    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override;

    ValidationResult validate_ommers(const Block& block, const BlockState& state) override;

    void initialize(EVM& evm) override;

    ValidationResult finalize(IntraBlockState& state, const Block& block, EVM& evm, const std::vector<Log>& logs) override;

    evmc::address get_beneficiary(const BlockHeader& header) override;

    BlockReward compute_reward(const Block& block) override;

  protected:
    ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) override;

  private:
    intx::uint256 terminal_total_difficulty_;
    RuleSetPtr pre_merge_rule_set_;
};

}  // namespace silkworm::protocol
