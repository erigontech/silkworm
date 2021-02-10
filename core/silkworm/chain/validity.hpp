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

#include <silkworm/state/buffer.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

// Classification of invalid transactions and blocks.
enum class [[nodiscard]] ValidationResult{
    kOk = 0,

    // See [YP] Section 4.3.2 "Holistic Validity", Eq (31)
    kWrongStateRoot, kWrongOmmersHash, kWrongTransactionsRoot, kWrongReceiptsRoot, kWrongLogsBloom,

    // See [YP] Section 4.3.4 "Block Header Validity", Eq (50)
    kUnknownParent,      // P(H) = ∅ ∨ Hi ≠ P(H)Hi + 1
    kWrongDifficulty,    // Hd ≠ D(H)
    kGasAboveLimit,      // Hg > Hl
    kInvalidGasLimit,    // |Hl-P(H)Hl|≥P(H)Hl/1024 ∨ Hl<5000
    kInvalidTimestamp,   // Hs ≤ P(H)Hs
    kWrongDaoExtraData,  // see EIP-779

    // See [YP] Section 6.2 "Execution", Eq (58)
    kMissingSender,         // S(T) = ∅
    kWrongNonce,            // Tn ≠ σ[S(T)]n
    kIntrinsicGas,          // g0 > Tg
    kInsufficientFunds,     // v0 > σ[S(T)]b
    kBlockGasLimitReached,  // Tg > BHl - l(BR)u

    // See [YP] Section 11.1 "Ommer Validation", Eq (157)
    kTooManyOmmers,       // ‖BU‖ > 2
    kInvalidOmmerHeader,  // ¬V(U)
    kNotAnOmmer,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer,      // not well covered by the YP actually

    // See [YP] Section 11.2 "Transaction Validation", Eq (160)
    kWrongBlockGas,  // BHg ≠ l(BR)u
};

// Performs validation of block header & body that can be done prior to execution.
// See [YP] Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity",
// and 11.1 "Ommer Validation".
// Shouldn't be used for genesis block.
ValidationResult pre_validate_block(const Block& block, const StateBuffer& state,
                                    const ChainConfig& config = kMainnetConfig);

// See [YP] Section 4.3.4 "Block Header Validity".
// Shouldn't be used for genesis block.
ValidationResult validate_block_header(const BlockHeader& header, const StateBuffer& state,
                                       const ChainConfig& config = kMainnetConfig);

}  // namespace silkworm

#endif  // SILKWORM_CHAIN_VALIDITY_HPP_
