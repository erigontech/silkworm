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

#ifndef SILKWORM_CONSENSUS_ENGINE_HPP_
#define SILKWORM_CONSENSUS_ENGINE_HPP_

#include <unordered_map>
#include <vector>

#include <silkworm/consensus/validation.hpp>
#include <silkworm/execution/state_pool.hpp>
#include <silkworm/state/intra_block_state.hpp>
#include <silkworm/state/state.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm::consensus {

class ConsensusEngine {
  public:
    //! \brief Performs validation of block header & body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \param [in] config: current chain config.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult pre_validate_block(const Block& block, State& state, const ChainConfig& config) = 0;

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] state: current state.
    //! \param [in] config: current chain config.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block_header(const BlockHeader& header, State& state,
                                                   const ChainConfig& config) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \param [in] revision: EVM fork.
    virtual void apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    virtual evmc::address get_beneficiary(const BlockHeader& header) = 0;

    virtual ~ConsensusEngine() = default;
};

// Performs validation of a transaction that can be done prior to sender recovery and block execution.
// May return kIntrinsicGas, kInvalidSignature, kWrongChainId, kUnsupportedTransactionType, or kOk.
ValidationResult pre_validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                          const std::optional<intx::uint256>& base_fee_per_gas);

// https://eips.ethereum.org/EIPS/eip-1559
std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header, const BlockHeader& parent,
                                                       const ChainConfig& config);

std::unique_ptr<ConsensusEngine> get_consensus_engine(SealEngineType engine_type);

}  // namespace silkworm::consensus

#endif  // SILKWORM_CONSENSUS_ENGINE_HPP_
