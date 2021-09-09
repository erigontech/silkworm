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

#include <silkworm/execution/state_pool.hpp>
#include <silkworm/state/state.hpp>
#include <silkworm/types/receipt.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/state/intra_block_state.hpp>

namespace silkworm::consensus {

// Classification of invalid transactions and blocks.
enum class [[nodiscard]] ValidationResult{
    kOk = 0,

    // See [YP] Section 4.3.2 "Holistic Validity", Eq (31)
    kWrongStateRoot = 1,         // wrong Hr
    kWrongOmmersHash = 2,        // wrong Ho
    kWrongTransactionsRoot = 3,  // wrong Ht
    kWrongReceiptsRoot = 4,      // wrong He
    kWrongLogsBloom = 5,         // wrong Hb

    // See [YP] Section 4.3.4 "Block Header Validity", Eq (50)
    kUnknownParent = 6,       // P(H) = ∅ ∨ Hi ≠ P(H)Hi + 1
    kWrongDifficulty = 7,     // Hd ≠ D(H)
    kGasAboveLimit = 8,       // Hg > Hl
    kInvalidGasLimit = 9,     // |Hl-P(H)Hl|≥P(H)Hl/1024 ∨ Hl<5000
    kInvalidTimestamp = 10,   // Hs ≤ P(H)Hs
    kExtraDataTooLong = 11,   // ‖Hx‖ > 32
    kWrongDaoExtraData = 12,  // see EIP-779
    kWrongBaseFee = 13,       // see EIP-1559
    kInvalidSeal = 14,        // Nonce or mix_hash

    // See [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender = 15,                 // S(T) = ∅
    kSenderNoEOA = 16,                   // EIP-3607: σ[S(T)]c ≠ KEC( () )
    kWrongNonce = 17,                    // Tn ≠ σ[S(T)]n
    kIntrinsicGas = 18,                  // g0 > Tg
    kInsufficientFunds = 19,             // v0 > σ[S(T)]b
    kBlockGasLimitExceeded = 20,         // Tg > BHl - l(BR)u
    kMaxFeeLessThanBase = 21,            // max_fee_per_gas < base_fee_per_gas (EIP-1559)
    kMaxPriorityFeeGreaterThanMax = 22,  // max_priority_fee_per_gas > max_fee_per_gas (EIP-1559)

    // See [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers = 23,       // ‖BU‖ > 2
    kInvalidOmmerHeader = 24,  // ¬V(U)
    kNotAnOmmer = 25,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer = 26,      // not well covered by the YP actually

    // See [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas = 27,  // BHg ≠ l(BR)u

    kInvalidSignature = 28,  // EIP-2

    kWrongChainId = 29,  // EIP-155

    kUnsupportedTransactionType = 30,  // EIP-2718
};

class ConsensusEngine {
    public:

    //! \brief Performs validation of block header & body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity", and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \param [in] config: current chain config.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult pre_validate_block(const Block& block, const State& state, const ChainConfig& config) = 0;

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] state: current state.
    //! \param [in] config: current chain config.
    //! \note Shouldn't be used for genesis block.
    virtual ValidationResult validate_block_header(const BlockHeader& header, const State& state, const ChainConfig& config) = 0;

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] state: current state.
    //! \param [in] block: current block to apply rewards for.
    //! \param [in] revision: EVM fork.
    virtual void apply_rewards(IntraBlockState& state, const Block& block, const evmc_revision& revision) = 0;
};

// Performs validation of a transaction that can be done prior to sender recovery and block execution.
// May return kIntrinsicGas, kInvalidSignature, kWrongChainId, kUnsupportedTransactionType, or kOk.
ValidationResult pre_validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                          const std::optional<intx::uint256>& base_fee_per_gas);

std::optional<BlockHeader> get_parent(const State& state, const BlockHeader& header);

// https://eips.ethereum.org/EIPS/eip-1559
std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& header, const BlockHeader& parent,
                                                              const ChainConfig& config);

bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                   const evmc::bytes32& mainline_hash, unsigned n, const State& state,
                   std::vector<BlockHeader>& old_ommers);

ConsensusEngine& get_consensus_engine(SealEngineType engine_type);

}

#endif // SILKWORM_CONSENSUS_ENGINE_HPP_
