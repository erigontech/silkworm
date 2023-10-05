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

#include <silkworm/core/state/intra_block_state.hpp>
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
    kInvalidSeal,                   // Nonce or mix_hash (invalid Proof of Work)

    kMissingField,     // e.g. missing withdrawals in a post-Shanghai block
    kFieldBeforeFork,  // e.g. withdrawals present in a pre-Shanghai block

    // [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender,          // S(T) = ∅
    kSenderNoEOA,            // EIP-3607: σ[S(T)]c ≠ KEC( () )
    kWrongNonce,             // Tn ≠ σ[S(T)]n
    kIntrinsicGas,           // g0 > Tg
    kInsufficientFunds,      // v0 > σ[S(T)]b
    kBlockGasLimitExceeded,  // Tg > BHl - l(BR)u

    // [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers,       // ‖BU‖ > 2
    kInvalidOmmerHeader,  // ¬V(U)
    kNotAnOmmer,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer,      // not well covered by the YP actually

    // [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas,  // BHg ≠ l(BR)u

    // Various other transaction validation
    kInvalidSignature,            // EIP-2
    kWrongChainId,                // EIP-155
    kUnsupportedTransactionType,  // EIP-2718
    kNonceTooHigh,                // Tn ≥ 2^64 - 1 (EIP-2681)

    // EIP-1559: Fee market change for ETH 1.0 chain
    kWrongBaseFee,
    kMaxFeeLessThanBase,            // max_fee_per_gas < base_fee_per_gas
    kMaxPriorityFeeGreaterThanMax,  // max_priority_fee_per_gas > max_fee_per_gas

    // EIP-3675: Upgrade consensus to Proof-of-Stake
    kInvalidNonce,  // Hn != 0 in a PoS block
    kPoSBlockBeforeMerge,
    kPoWBlockAfterMerge,

    // EIP-3860: Limit and meter initcode
    kMaxInitCodeSizeExceeded,

    // EIP-4895: Beacon chain push withdrawals as operations
    kWrongWithdrawalsRoot,

    // EIP-4844: Shard Blob Transactions
    kWrongBlobGasUsed,
    kWrongExcessBlobGas,
    kNoBlobs,
    kTooManyBlobs,
    kWrongBlobCommitmentVersion,
    kMaxFeePerBlobGasTooLow,  // max_fee_per_blob_gas < blob_gas_price
    kBlobCreateTransaction,   // Blob transactions cannot have the form of a create transaction

    // Bor validation errors. See https://github.com/ledgerwatch/erigon/blob/devel/consensus/bor/bor.go
    kMissingVanity,     // Block's extra-data section is shorter than 32 bytes, which is required to store the signer vanity
    kMissingSignature,  // Block's extra-data section doesn't seem to contain a 65 byte secp256k1 signature
    kInvalidMixDigest,  // Block's mix digest is non-zero
};

namespace protocol {

    bool transaction_type_is_supported(TransactionType, evmc_revision);

    //! \brief First part of transaction validation that can be done prior to sender recovery
    //! and without access to the state.
    //! \remarks Should sender of transaction not yet recovered a check on signature's validity is performed
    //! \remarks These function is agnostic to whole block validity
    ValidationResult pre_validate_transaction(const Transaction& txn, evmc_revision revision, uint64_t chain_id,
                                              const std::optional<intx::uint256>& base_fee_per_gas,
                                              const std::optional<intx::uint256>& blob_gas_price);

    ValidationResult pre_validate_transactions(const Block& block, const ChainConfig& config);

    //! \brief Final part of transaction validation that requires access to the state.
    //!
    //! Preconditions:
    //! 1) pre_validate_transaction(txn) must return kOk
    //! 2) txn.from must be recovered, otherwise kMissingSender will be returned
    ValidationResult validate_transaction(const Transaction& txn, const IntraBlockState& state,
                                          uint64_t available_gas) noexcept;

    //! \see EIP-1559: Fee market change for ETH 1.0 chain
    intx::uint256 expected_base_fee_per_gas(const BlockHeader& parent);

    //! \see EIP-4844: Shard Blob Transactions
    uint64_t calc_excess_blob_gas(const BlockHeader& parent);

    //! \brief Calculate the transaction root of a block body
    evmc::bytes32 compute_transaction_root(const BlockBody& body);

    //! \brief Calculate the withdrawals root of a block body
    std::optional<evmc::bytes32> compute_withdrawals_root(const BlockBody& body);

    //! \brief Calculate the hash of ommers of a block body
    evmc::bytes32 compute_ommers_hash(const BlockBody& body);

}  // namespace protocol

}  // namespace silkworm
