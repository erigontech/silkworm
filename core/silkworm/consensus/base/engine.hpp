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
#ifndef SILKWORM_CONSENSUS_BASE_ENGINE_HPP_
#define SILKWORM_CONSENSUS_BASE_ENGINE_HPP_

#include <silkworm/consensus/engine.hpp>

namespace silkworm::consensus {

class EngineBase : public IEngine {
  public:
    explicit EngineBase(const ChainConfig& chain_config, bool prohibit_ommers)
        : chain_config_{chain_config}, prohibit_ommers_{prohibit_ommers} {}

    //! \brief Performs validation of block header & body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    ValidationResult pre_validate_block(const Block& block, const BlockState& state) override;

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] with_future_timestamp_check : whether to check header timestamp is in the future wrt host current
    //! time \see https://github.com/torquem-ch/silkworm/issues/448
    //! \note Shouldn't be used for genesis block.
    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    evmc::address get_beneficiary(const BlockHeader& header) override;

    //! \brief Validates the difficulty of the header
    virtual ValidationResult validate_difficulty(const BlockHeader& header, const BlockHeader& parent) = 0;

    //! \brief See https://eips.ethereum.org/EIPS/eip-1559
    std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header, const BlockHeader& parent);

    //! \brief Returns parent header (if any) of provided header
    static std::optional<BlockHeader> get_parent_header(const BlockState& state, const BlockHeader& header);

  protected:
    const ChainConfig& chain_config_;
    bool prohibit_ommers_{false};

    //! \brief See [YP] Section 11.1 "Ommer Validation"
    bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                const evmc::bytes32& mainline_hash, unsigned int n, const BlockState& state,
                std::vector<BlockHeader>& old_ommers);
};

}  // namespace silkworm::consensus

#endif  // SILKWORM_CONSENSUS_BASE_ENGINE_HPP_
