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

#pragma once
#ifndef SILKWORM_CONSENSUS_ETHASH_ENGINE_HPP_
#define SILKWORM_CONSENSUS_ETHASH_ENGINE_HPP_

#include <ethash/ethash.hpp>

#include <silkworm/consensus/base/engine.hpp>

namespace silkworm::consensus {

// Proof of Work implementation
class EthashEngine : public EngineBase {
  public:
    explicit EthashEngine(const ChainConfig& chain_config) : EngineBase(chain_config, /*prohibit_ommers=*/false) {}

    //! \brief Validates the seal of the header
    ValidationResult validate_seal(const BlockHeader& header) override;

    ValidationResult validate_difficulty(const BlockHeader& header, const BlockHeader& parent) override;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \param [in] revision: EVM fork.
    void finalize(IntraBlockState& state, const Block& block, evmc_revision revision) override;

  private:
    ethash::epoch_context_ptr epoch_context_{nullptr, ethash_destroy_epoch_context};
};

}  // namespace silkworm::consensus

#endif  // SILKWORM_CONSENSUS_ETHASH_ENGINE_HPP_
