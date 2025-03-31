// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <evmc/evmc.h>

#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/transaction.hpp>

namespace silkworm {

class EVM;

// Classification of invalid transactions and blocks.
enum class [[nodiscard]] ValidationResult {
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
    kInvalidSignature,            // EIP-2 violated or otherwise invalid signature
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

    // EIP-4844 and EIP 7702
    kProhibitedContractCreation,  // Blob and SetCode transactions cannot have the form of a create transaction

    // EIP-7702
    kEmptyAuthorizations,

    // EIP-7685: Requests root mismatch
    kRequestsRootMismatch,

    // EIP-7623: Increase calldata cost
    kFloorCost,

    // EIP-7702 Set EOA account code
    kIncorrectAuthorization,

    // Bor validation errors. See https://github.com/erigontech/erigon/blob/main/consensus/bor/bor.go
    kMissingVanity,          // Block's extra-data section is shorter than 32 bytes, which is required to store the signer vanity
    kMissingSignature,       // Block's extra-data section doesn't seem to contain a 65 byte secp256k1 signature
    kInvalidMixDigest,       // Block's mix digest is non-zero
    kExtraValidators,        // Non-sprint-end block contains extra validator list
    kInvalidSpanValidators,  // Invalid validator list on sprint end block
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
    //! Precondition:
    //! pre_validate_transaction(txn) must return kOk
    ValidationResult validate_transaction(const Transaction& txn, const IntraBlockState& state,
                                          uint64_t available_gas) noexcept;

    ValidationResult validate_call_precheck(const Transaction& txn, const EVM& evm) noexcept;

    ValidationResult pre_validate_common_base(const Transaction& txn, evmc_revision revision, uint64_t chain_id) noexcept;

    ValidationResult pre_validate_common_forks(const Transaction& txn, evmc_revision rev, const std::optional<intx::uint256>& blob_gas_price) noexcept;

    ValidationResult validate_call_funds(const Transaction& txn, const EVM& evm, const intx::uint256& owned_funds, bool bailout) noexcept;

    intx::uint256 compute_call_cost(const Transaction& txn, const intx::uint256& effective_gas_price, const EVM& evm);

    //! \see EIP-1559: Fee market change for ETH 1.0 chain
    intx::uint256 expected_base_fee_per_gas(const BlockHeader& parent);

    //! \see EIP-4844: Shard Blob Transactions
    uint64_t calc_excess_blob_gas(const BlockHeader& parent, evmc_revision revision);

    //! \brief Calculate the transaction root of a block body
    evmc::bytes32 compute_transaction_root(const BlockBody& body);

    //! \brief Calculate the withdrawals root of a block body
    std::optional<evmc::bytes32> compute_withdrawals_root(const BlockBody& body);

    //! \brief Calculate the hash of ommers of a block body
    evmc::bytes32 compute_ommers_hash(const BlockBody& body);

    //! \brief Calculates requests rook in block header
    ValidationResult validate_requests_root(const BlockHeader& header, const std::vector<Log>& logs, EVM& evm);

}  // namespace protocol

}  // namespace silkworm
