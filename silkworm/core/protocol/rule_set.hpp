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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm::protocol {

struct BlockReward {
    intx::uint256 miner;
    std::vector<intx::uint256> ommers;
};

class IRuleSet {
  public:
    virtual ~IRuleSet() = default;

    //! \brief Performs validation of block body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity" and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult pre_validate_block_body(const Block& block, const BlockState& state) = 0;

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] state: current state.
    //! \param [in] with_future_timestamp_check : whether to check header timestamp is in the future wrt host current
    //! time \see https://github.com/torquem-ch/silkworm/issues/448
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) = 0;

    //! \brief Validates the seal of the header
    virtual ValidationResult validate_seal(const BlockHeader& header) = 0;

    //! \brief Performs validation of block ommers only.
    //! \brief See [YP] Sections 11.1 "Ommer Validation".
    //! \param [in] block: block to validate.
    //! \param [in] state: current state.
    virtual ValidationResult validate_ommers(const Block& block, const BlockState& state) = 0;

    //! \brief Initializes block execution by applying changes stipulated by the protocol
    //! (e.g. storing parent beacon root)
    virtual void initialize(EVM& evm) = 0;

    //! \brief Finalizes block execution by applying changes stipulated by the protocol
    //! (e.g. block rewards, withdrawals)
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \remarks For Ethash See [YP] Section 11.3 "Reward Application".
    virtual void finalize(IntraBlockState& state, const Block& block) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    virtual evmc::address get_beneficiary(const BlockHeader& header) = 0;

    virtual BlockReward compute_reward(const Block& block) = 0;

    //! \brief Bor adds a transfer log after each transaction reflecting the gas fee transfer
    virtual void add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                                      const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                                      const intx::uint256& recipient_initial_balance) = 0;
};

using RuleSetPtr = std::unique_ptr<IRuleSet>;

//! \brief Creates an instance of the proper Rule Set on behalf of chain configuration
RuleSetPtr rule_set_factory(const ChainConfig& chain_config);

}  // namespace silkworm::protocol
