// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/protocol/rule_set.hpp>

namespace silkworm::protocol {

// See https://github.com/maticnetwork/bor/blob/master/consensus/bor/bor.go
class BorRuleSet : public RuleSet {
  public:
    explicit BorRuleSet(const ChainConfig& chain_config) : RuleSet(chain_config, /*prohibit_ommers=*/true) {}

    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override;

    void initialize(EVM&) override {}

    ValidationResult finalize(IntraBlockState&, const Block&, EVM&, const std::vector<Log>& logs) override;

    evmc::address get_beneficiary(const BlockHeader& header) override;

    void add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                              const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                              const intx::uint256& recipient_initial_balance) override;

    TransferFunc* transfer_func() const override;

  protected:
    ValidationResult validate_extra_data(const BlockHeader& header) const override;

    ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) override;

  private:
    const bor::Config& config() const;
};

}  // namespace silkworm::protocol
