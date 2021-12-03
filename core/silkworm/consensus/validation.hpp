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

#ifndef SILKWORM_CONSENSUS_VALIDATION_HPP_
#define SILKWORM_CONSENSUS_VALIDATION_HPP_

namespace silkworm {

// Classification of invalid transactions and blocks.
enum class [[nodiscard]] ValidationResult{
    kOk,                      // All checks passed
    kUnknownConsensusEngine,  // Undetectable consensus engine
    kFutureBlock,             // Block has a timestamp in the future

    // See [YP] Section 4.3.2 "Holistic Validity", Eq (31)
    kWrongStateRoot,         // wrong Hr
    kWrongOmmersHash,        // wrong Ho
    kWrongTransactionsRoot,  // wrong Ht
    kWrongReceiptsRoot,      // wrong He
    kWrongLogsBloom,         // wrong Hb

    // See [YP] Section 4.3.4 "Block Header Validity", Eq (50)
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

    // See [YP] Section 6.2 "Execution", Eq (58)
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

    // See [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers,       // ‖BU‖ > 2
    kInvalidOmmerHeader,  // ¬V(U)
    kNotAnOmmer,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer,      // not well covered by the YP actually

    // See [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas,  // BHg ≠ l(BR)u

    // See EIP-3675: Upgrade consensus to Proof-of-Stake
    kPoSBlockBeforeMerge,
    kPoWBlockAfterMerge,
};

}  // namespace silkworm

#endif  // SILKWORM_CONSENSUS_VALIDATION_HPP_
