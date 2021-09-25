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

#include <vector>

#include <silkworm/chain/config.hpp>
#include <silkworm/consensus/engine.hpp>
#include <silkworm/execution/processor.hpp>
#include <silkworm/state/state.hpp>
#include <silkworm/types/block.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm {

/** @brief Executes a given block and writes resulting changes into the state.
 *
 * Preconditions:
 *  pre_validate_block(block) must return kOk;
 *  transaction senders must be already populated.
 *
 * Warning: This method does not verify state root;
 * pre-Byzantium receipt root isn't validated either.
 *
 * For better performance use ExecutionProcessor directly and set EVM state_pool & advanced_analysis_cache.
 *
 * @param state The Ethereum state at the beginning of the block.
 */
[[nodiscard]] inline ValidationResult execute_block(const Block& block, State& state,
                                                    const ChainConfig& chain_config) noexcept {
    auto consensus_engine{consensus::engine_factory(chain_config)};
    if (!consensus_engine) {
        return ValidationResult::kUnknownConsensusEngine;
    }
    ExecutionProcessor processor{block, *consensus_engine, state, chain_config};
    std::vector<Receipt> receipts;
    return processor.execute_and_write_block(receipts);
}

}  // namespace silkworm

#endif  // SILKWORM_EXECUTION_EXECUTION_HPP_
