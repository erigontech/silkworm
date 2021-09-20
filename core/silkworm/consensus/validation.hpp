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
    kInvalidSeal = 14,        // Nonce or mix_hash (invalid Proof of Work)
    kInvalidMixHash = 15,     // Invalid mix_hash (Clique, EIP-225)

    // See [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender = 16,          // S(T) = ∅
    kSenderNoEOA = 17,            // EIP-3607: σ[S(T)]c ≠ KEC( () )
    kWrongNonce = 18,             // Tn ≠ σ[S(T)]n
    kIntrinsicGas = 19,           // g0 > Tg
    kInsufficientFunds = 20,      // v0 > σ[S(T)]b
    kBlockGasLimitExceeded = 21,  // Tg > BHl - l(BR)u

    // Various other transaction validation
    kMaxFeeLessThanBase = 22,            // max_fee_per_gas < base_fee_per_gas (EIP-1559)
    kMaxPriorityFeeGreaterThanMax = 23,  // max_priority_fee_per_gas > max_fee_per_gas (EIP-1559)
    kInvalidSignature = 24,              // EIP-2
    kWrongChainId = 25,                  // EIP-155
    kUnsupportedTransactionType = 26,    // EIP-2718

    // See [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers = 27,       // ‖BU‖ > 2
    kInvalidOmmerHeader = 28,  // ¬V(U)
    kNotAnOmmer = 29,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer = 30,      // not well covered by the YP actually

    // See [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas = 31,  // BHg ≠ l(BR)u

    // Clique (EIP-225)
    kUnauthorizedSigner = 32,  // Handling an unauthorized voting signer
    kMissingSigner = 33,       // Missing Signer in extra_data
    kRecentlySigned = 34,      // Signer has already recently signed
    kInvalidVote = 35,         // Non-Existing vote option
    kInvalidCheckpointBeneficiary = 36,
    kMissingVanity = 37,  // ‖Hx‖ < 32+65
};

}  // namespace silkworm

#endif  // SILKWORM_CONSENSUS_VALIDATION_HPP_
