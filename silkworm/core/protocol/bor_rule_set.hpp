/*
   Copyright 2023 The Silkworm Authors

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

#include <silkworm/core/protocol/base_rule_set.hpp>

namespace silkworm::protocol {

// See https://github.com/maticnetwork/bor/blob/master/consensus/bor/bor.go
class BorRuleSet : public BaseRuleSet {
  public:
    explicit BorRuleSet(const ChainConfig& chain_config) : BaseRuleSet(chain_config, /*prohibit_ommers=*/true) {}

    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override;

    void initialize(EVM&) override {}

    void finalize(IntraBlockState&, const Block&) override;

    evmc::address get_beneficiary(const BlockHeader& header) override;

    void add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                              const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                              const intx::uint256& recipient_initial_balance) override;

  protected:
    ValidationResult validate_extra_data(const BlockHeader& header) const override;

    ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) override;

  private:
    [[nodiscard]] const BorConfig& config() const;
};

}  // namespace silkworm::protocol
