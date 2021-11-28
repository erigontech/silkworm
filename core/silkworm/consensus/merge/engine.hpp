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

#ifndef SILKWORM_CONSENSUS_MERGE_ENGINE_HPP_
#define SILKWORM_CONSENSUS_MERGE_ENGINE_HPP_

#include <silkworm/consensus/ethash/engine.hpp>
#include <silkworm/consensus/pos/engine.hpp>

namespace silkworm::consensus {

// Mainnet consensus engine that can handle blocks before, during, and after the Merge.
// See EIP-3675: Upgrade consensus to Proof-of-Stake.
class MergeEngine : public IEngine {
  public:
    explicit MergeEngine(const ChainConfig& chain_config);

    ValidationResult pre_validate_block(const Block& block, const BlockState& state) override;

    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override;

    ValidationResult validate_seal(const BlockHeader& header) override;

    void finalize(IntraBlockState& state, const Block& block, evmc_revision revision) override;

    evmc::address get_beneficiary(const BlockHeader& header) override;

  private:
    bool terminal_pow_block(const BlockHeader& header, const BlockState& state) const;

    intx::uint256 terminal_total_difficulty_;
    EthashEngine ethash_engine_;
    ProofOfStakeEngine pos_engine_;
};

}  // namespace silkworm::consensus

#endif  // SILKWORM_CONSENSUS_MERGE_ENGINE_HPP_
