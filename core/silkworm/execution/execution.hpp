/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_EXECUTION_EXECUTION_H_
#define SILKWORM_EXECUTION_EXECUTION_H_

#include <silkworm/chain/config.hpp>
#include <silkworm/execution/analysis_cache.hpp>
#include <silkworm/execution/state_pool.hpp>
#include <silkworm/state/buffer.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>
#include <stdexcept>

namespace silkworm {

// Classification of invalid transcations and blocks.
// See Yellow Paper [YP], Sections 4.3.2 "Holistic Validity", 4.3.4 "Block Header Validity",
// 6.2 "Execution", and 11 "Block Finalisation".
enum class ValidationError {
    kOk = 0,
    kMissingSender,         // S(T) = ∅,           see [YP] Eq (58)
    kInvalidNonce,          // Tn ≠ σ[S(T)]n,      see [YP] Eq (58)
    kIntrinsicGas,          // g0 > Tg,            see [YP] Eq (58)
    kInsufficientFunds,     // v0 > σ[S(T)]b,      see [YP] Eq (58)
    kBlockGasLimitReached,  // Tg > BHl - l(BR)u,  see [YP] Eq (58)
    kBlockGasMismatch,      // BHg  ≠ l(BR)u,      see [YP] Eq (160)
    kReceiptRootMismatch,   // wrong receipt root, see [YP] Eq (31)
};

/** @brief Executes a given block and writes resulting changes into the database.
 *
 * Transaction senders must be already populated.
 * The DB table kCurrentState should match the Ethereum state at the begining of the block.
 *
 * For better performance use AnalysisCache & ExecutionStatePool.
 */
std::pair<std::vector<Receipt>, ValidationError> execute_block(const Block& block, StateBuffer& buffer,
                                                               const ChainConfig& config = kMainnetConfig,
                                                               AnalysisCache* analysis_cache = nullptr,
                                                               ExecutionStatePool* state_pool = nullptr) noexcept;

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_EXECUTION_H_
