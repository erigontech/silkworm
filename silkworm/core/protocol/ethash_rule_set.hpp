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

#include <ostream>

#include <ethash/ethash.hpp>

#include <silkworm/core/protocol/rule_set.hpp>

namespace silkworm::protocol {

// Proof of Work implementation
class EthashRuleSet : public RuleSet {
  public:
    explicit EthashRuleSet(const ChainConfig& chain_config) : RuleSet(chain_config, /*prohibit_ommers=*/false) {}

    void initialize(EVM& evm) override;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    ValidationResult finalize(IntraBlockState& state, const Block& block, EVM& evm, const std::vector<Log>& logs) override;

    BlockReward compute_reward(const Block& block) override;

    // Canonical difficulty of a Proof-of-Work block header.
    // See Section 4.3.4 "Block Header Validity" of the Yellow Paper and also
    // EIP-2, EIP-100, EIP-649, EIP-1234, EIP-2384, EIP-3554, EIP-4345.
    static intx::uint256 difficulty(
        uint64_t block_num,
        uint64_t block_timestamp,
        const intx::uint256& parent_difficulty,
        uint64_t parent_timestamp,
        bool parent_has_uncles,
        const ChainConfig& config);

  protected:
    ValidationResult validate_extra_data(const BlockHeader& header) const override;

    ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) override;

  private:
    ethash::epoch_context_ptr epoch_context_{nullptr, ethash_destroy_epoch_context};
};

}  // namespace silkworm::protocol
