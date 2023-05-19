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

#include <optional>

#include <evmc/evmc.h>

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

// Classification of invalid transactions and blocks.
enum class [[nodiscard]] ValidationResult{
    kOk,  // All checks passed

    kUnknownProtocolRuleSet,  // Unsupported protocol rule set
    kFutureBlock,             // Block has a timestamp in the future

    // [YP] Section 4.3.2 "Holistic Validity", Eq (31)
    kWrongStateRoot,         // wrong Hr
    kWrongOmmersHash,        // wrong Ho
    kWrongTransactionsRoot,  // wrong Ht
    kWrongReceiptsRoot,      // wrong He
    kWrongLogsBloom,         // wrong Hb

    // [YP] Section 4.3.4 "Block Header Validity", Eq (50)
    kUnknownParent,                 // P(H) = ∅ ∨ Hi ≠ P(H)Hi + 1
    kUnknownParentTotalDifficulty,  // failed to look up parent's total difficulty
    kWrongDifficulty,               // Hd ≠ D(H)
    kGasAboveLimit,                 // Hg > Hl
    kInvalidGasLimit,               // |Hl-P(H)Hl|≥P(H)Hl/1024 ∨ Hl<5000
    kInvalidTimestamp,              // Hs ≤ P(H)Hs
    kExtraDataTooLong,              // ‖Hx‖ > 32
    kWrongDaoExtraData,             // see EIP-779
    kWrongBaseFee,                  // see EIP-1559
    kInvalidSeal,                   // Nonce or mix_hash (invalid Proof of Work)
    kInvalidNonce,                  // Hn != 0 (Proof of State, EIP-3675)

    // [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender,          // S(T) = ∅
    kSenderNoEOA,            // EIP-3607: σ[S(T)]c ≠ KEC( () )
    kWrongNonce,             // Tn ≠ σ[S(T)]n
    kIntrinsicGas,           // g0 > Tg
    kInsufficientFunds,      // v0 > σ[S(T)]b
    kBlockGasLimitExceeded,  // Tg > BHl - l(BR)u

    // Various other transaction validation
    kMaxFeeLessThanBase,            // max_fee_per_gas < base_fee_per_gas (EIP-1559)
    kMaxPriorityFeeGreaterThanMax,  // max_priority_fee_per_gas > max_fee_per_gas (EIP-1559)
    kInvalidSignature,              // EIP-2
    kWrongChainId,                  // EIP-155
    kUnsupportedTransactionType,    // EIP-2718
    kNonceTooHigh,                  // Tn ≥ 2^64 - 1 (EIP-2681)

    // [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers,       // ‖BU‖ > 2
    kInvalidOmmerHeader,  // ¬V(U)
    kNotAnOmmer,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer,      // not well covered by the YP actually

    // [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas,  // BHg ≠ l(BR)u

    // EIP-3675: Upgrade consensus to Proof-of-Stake
    kPoSBlockBeforeMerge,
    kPoWBlockAfterMerge,

    // EIP-3860: Limit and meter initcode
    kMaxInitCodeSizeExceeded,

    // EIP-4895: Beacon chain push withdrawals as operations
    kMissingWithdrawals,
    kUnexpectedWithdrawals,
    kWrongWithdrawalsRoot,

    // EIP-4844: Shard Blob Transactions
    kWrongExcessDataGas,
    kNoBlobs,
    kTooManyBlobs,
    kWrongBlobCommitmentVersion,
    kMaxFeePerDataGasTooLow,  // max_fee_per_data_gas < data_gas_price
};

namespace protocol {

    bool transaction_type_is_supported(TransactionType, evmc_revision);

    //! \brief Performs validation of a transaction that can be done prior to sender recovery and block execution.
    //! \remarks Should sender of transaction not yet recovered a check on signature's validity is performed
    //! \remarks These function is agnostic to whole block validity
    ValidationResult pre_validate_transaction(const Transaction& txn, evmc_revision revision, uint64_t chain_id,
                                              const std::optional<intx::uint256>& base_fee_per_gas,
                                              const std::optional<intx::uint256>& data_gas_price);

    ValidationResult pre_validate_transactions(const Block& block, const ChainConfig& config);

    //! \see EIP-1559: Fee market change for ETH 1.0 chain
    std::optional<intx::uint256> expected_base_fee_per_gas(const BlockHeader& parent, const evmc_revision);

    //! \see EIP-4844: Shard Blob Transactions
    std::optional<intx::uint256> calc_excess_data_gas(const BlockHeader& parent, std::size_t num_blobs,
                                                      const evmc_revision);

    //! \brief Calculate the transaction root of a block body
    evmc::bytes32 compute_transaction_root(const BlockBody& body);

    //! \brief Calculate the withdrawals root of a block body
    std::optional<evmc::bytes32> compute_withdrawals_root(const BlockBody& body);

    //! \brief Calculate the hash of ommers of a block body
    evmc::bytes32 compute_ommers_hash(const BlockBody& body);

}  // namespace protocol

}  // namespace silkworm
