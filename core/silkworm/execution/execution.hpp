/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_EXECUTION_EXECUTION_HPP_
#define SILKWORM_EXECUTION_EXECUTION_HPP_

#include <stdexcept>

#include <silkworm/chain/config.hpp>
#include <silkworm/chain/validity.hpp>
#include <silkworm/execution/analysis_cache.hpp>
#include <silkworm/execution/state_pool.hpp>
#include <silkworm/state/buffer.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm {

/** @brief Executes a given block and writes resulting changes into the database.
 *
 * Transaction senders must be already populated.
 * kPlainState DB table (+auxilary tables) should match the Ethereum state at the begining of the block.
 *
 * Another precondition: pre_validate_block(block) must return kOk.
 *
 * Warning: This method does not verify state root;
 * pre-Byzantium receipt root isn't validated either.
 *
 * For better performance use AnalysisCache & ExecutionStatePool.
 */
[[nodiscard]] ValidationResult execute_block(const Block& block, StateBuffer& buffer, const ChainConfig& config,
                                             std::vector<Receipt>& out, AnalysisCache* analysis_cache = nullptr,
                                             ExecutionStatePool* state_pool = nullptr,
                                             evmc_vm* exo_evm = nullptr) noexcept;

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_EXECUTION_HPP_
