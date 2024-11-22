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
