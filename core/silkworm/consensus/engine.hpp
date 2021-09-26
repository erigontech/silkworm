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

class IConsensusEngine {
  public:
    explicit IConsensusEngine(const ChainConfig& chain_config) : chain_config_{chain_config} {};
    virtual ~IConsensusEngine() = default;

    //! \brief Performs validation of block header & body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block(const Block& block, State& state) = 0;

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block_header(const BlockHeader& header, State& state) = 0;

    //! \brief Validates the seal of the header
    virtual ValidationResult validate_seal(const BlockHeader& header) {
        (void)header;
        return ValidationResult::kOk;
    }

    //! \brief Finalizes consensus tasks by applying changes in the state of accounts or of the consensus itself
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \param [in] revision: EVM fork.
    //! \remarks For Ethash See [YP] Section 11.3 "Reward Application".
    virtual void finalize(IntraBlockState& state, const Block& block, const evmc_revision& revision) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    virtual evmc::address get_beneficiary(const BlockHeader& header) = 0;

    //! \brief Returns parent header (if any) of provided header
    virtual std::optional<BlockHeader> get_parent_header(const State& state, const BlockHeader& header) = 0;

  protected:
    const ChainConfig& chain_config_;

    //! \brief See [YP] Section 11.1 "Ommer Validation"
    virtual bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                        const evmc::bytes32& mainline_hash, unsigned n, const State& state,
                        std::vector<BlockHeader>& old_ommers) = 0;

    //! \brief See https://eips.ethereum.org/EIPS/eip-1559
    virtual std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header,
                                                                   const BlockHeader& parent) = 0;
};

//! \brief Performs a validation of a transaction.
//! \return Any of kIntrinsicGas, kInvalidSignature, kWrongChainId, kUnsupportedTransactionType, or kOk.
//! \remarks Should sender of transaction not yet recovered a check on signature's validity is performed
//! \remarks These function is agnostic to whole block validity
ValidationResult validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                      const std::optional<intx::uint256>& base_fee_per_gas);

//! \brief Creates an instance of proper Consensus Engine on behalf of chain configuration
std::unique_ptr<IConsensusEngine> engine_factory(const ChainConfig& chain_config);

}  // namespace silkworm::consensus

#endif  // SILKWORM_CONSENSUS_ENGINE_HPP_
