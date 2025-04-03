// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <ostream>

#include <gsl/pointers>

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

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& out, const BlockReward& reward);

// Abstract class representing a set of protocol rules.
// For example, its subclass BorRuleSet corresponds to the protocol rule set of Polygon PoS.
class RuleSet {
  public:
    // Only movable
    RuleSet(RuleSet&& other) = default;
    RuleSet& operator=(RuleSet&& other) = default;

    virtual ~RuleSet() = default;

    //! \brief Performs validation of block body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity" and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult pre_validate_block_body(const Block& block, const BlockState& state);

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] state: current state.
    //! \param [in] with_future_timestamp_check : whether to check header timestamp is in the future wrt host current
    //! time \see https://github.com/erigontech/silkworm/issues/448
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check);

    //! \brief Performs validation of block ommers only.
    //! \brief See [YP] Sections 11.1 "Ommer Validation".
    //! \param [in] block: block to validate.
    //! \param [in] state: current state.
    virtual ValidationResult validate_ommers(const Block& block, const BlockState& state);

    //! \brief Initializes block execution by applying changes stipulated by the protocol
    //! (e.g. storing parent beacon root)
    virtual void initialize(EVM& evm) = 0;

    //! \brief Finalizes block execution by applying changes stipulated by the protocol
    //! (e.g. block rewards, withdrawals)
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \remarks For Ethash See [YP] Section 11.3 "Reward Application".
    virtual ValidationResult finalize(IntraBlockState& state, const Block& block, EVM& evm, const std::vector<Log>& logs) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    virtual evmc::address get_beneficiary(const BlockHeader& header);

    virtual BlockReward compute_reward(const Block& block);

    //! \brief Bor adds a transfer log after each transaction reflecting the gas fee transfer
    virtual void add_fee_transfer_log(IntraBlockState& state, const intx::uint256& amount, const evmc::address& sender,
                                      const intx::uint256& sender_initial_balance, const evmc::address& recipient,
                                      const intx::uint256& recipient_initial_balance);

    virtual TransferFunc* transfer_func() const { return standard_transfer; }

  protected:
    explicit RuleSet(const ChainConfig& chain_config, bool prohibit_ommers)
        : chain_config_{&chain_config}, prohibit_ommers_{prohibit_ommers} {}

    virtual ValidationResult validate_extra_data(const BlockHeader& header) const;

    //! \brief Validates the difficulty and the seal of the header
    //! \note Used by validate_block_header
    virtual ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) = 0;

    //! \brief Returns parent header (if any) of provided header
    static std::optional<BlockHeader> get_parent_header(const BlockState& state, const BlockHeader& header);

    gsl::not_null<const ChainConfig*> chain_config_;

  private:
    //! \brief See [YP] Section 11.1 "Ommer Validation"
    static bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                       const evmc::bytes32& mainline_hash, unsigned int n, const BlockState& state,
                       std::vector<BlockHeader>& old_ommers);

    bool prohibit_ommers_{false};
};

using RuleSetPtr = std::unique_ptr<RuleSet>;

//! \brief Creates an instance of the proper Rule Set on behalf of chain configuration
RuleSetPtr rule_set_factory(const ChainConfig& chain_config);

}  // namespace silkworm::protocol
