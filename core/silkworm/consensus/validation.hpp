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
    kUnauthorizedSigner = 30,  // Handling an unhautorized voting signer
    kMissingSigner = 31,   // Missing Signer in extra_data
    kRecentlySigned = 32, // Signer has already recently signed
    kInvalidVote = 33, // Non-Existing vote option
    kInvalidCheckpointBeneficiary = 34,
    kMissingVanity = 35,   // ‖Hx‖ < 97

    kUnsupportedTransactionType = 36,  // EIP-2718
};

#endif // SILKWORM_CONSENSUS_VALIDATION_HPP_