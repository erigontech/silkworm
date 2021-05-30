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

#ifndef SILKWORM_CHAIN_VALIDITY_HPP_
#define SILKWORM_CHAIN_VALIDITY_HPP_

#include <optional>

#include <silkworm/state/buffer.hpp>
#include <silkworm/types/block.hpp>

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
    kInvalidSeal = 14,        // Nonce or mix_hash

    // See [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender = 15,                 // S(T) = ∅
    kWrongNonce = 16,                    // Tn ≠ σ[S(T)]n
    kIntrinsicGas = 17,                  // g0 > Tg
    kInsufficientFunds = 18,             // v0 > σ[S(T)]b
    kBlockGasLimitExceeded = 19,         // Tg > BHl - l(BR)u
    kMaxFeeLessThanBase = 20,            // max_fee_per_gas < base_fee_per_gas (EIP-1559)
    kMaxPriorityFeeGreaterThanMax = 21,  // max_priority_fee_per_gas > max_fee_per_gas (EIP-1559)

    // See [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers = 22,       // ‖BU‖ > 2
    kInvalidOmmerHeader = 23,  // ¬V(U)
    kNotAnOmmer = 24,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer = 25,      // not well covered by the YP actually

    // See [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas = 26,  // BHg ≠ l(BR)u

    kInvalidSignature = 27,  // EIP-2

    kWrongChainId = 28,  // EIP-155

    kUnsupportedTransactionType = 29,  // EIP-2718
};

// Performs validation of a transaction that can be done prior to sender recovery and block execution.
// May return kIntrinsicGas, kInvalidSignature, kWrongChainId, kUnsupportedTransactionType, or kOk.
ValidationResult pre_validate_transaction(const Transaction& txn, uint64_t block_number, const ChainConfig& config,
                                          const std::optional<intx::uint256>& base_fee_per_gas);

// Performs validation of block header & body that can be done prior to sender recovery and execution.
// See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity",
// and 11.1 "Ommer Validation".
// Shouldn't be used for genesis block.
ValidationResult pre_validate_block(const Block& block, const StateBuffer& state, const ChainConfig& config);

// See [YP] Section 4.3.4 "Block Header Validity".
// Shouldn't be used for genesis block.
ValidationResult validate_block_header(const BlockHeader& header, const StateBuffer& state, const ChainConfig& config);

}  // namespace silkworm

#endif  // SILKWORM_CHAIN_VALIDITY_HPP_
