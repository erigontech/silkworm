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

#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/processor.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

/**
 * @brief Execute a given block, write resulting changes into the state and return the transaction receipts.
 * @attention This \code execute_block overload requires both EVM state_pool and analysis_cache to better performance
 * @precondition validate_block_header & pre_validate_block_body must return kOk; transaction senders must be already populated.
 * @warning This method does not verify state root; pre-Byzantium receipt root isn't validated either.
 * @param block The block to execute.
 * @param analysis_cache The cache containing the EVM code analysis indexed by code hash.
 * @param state_pool The pool of EVM execution states to use.
 * @param state The chain state at the beginning of the block.
 * @param chain_config The configuration parameters for the chain.
 * @param receipts The transaction receipts produced by block execution.
 */
[[nodiscard]] inline ValidationResult execute_block(const Block& block,
                                                    AnalysisCache& analysis_cache,
                                                    ObjectPool<evmone::ExecutionState>& state_pool,
                                                    State& state,
                                                    const ChainConfig& chain_config,
                                                    std::vector<Receipt>& receipts) noexcept {
    const auto rule_set{protocol::rule_set_factory(chain_config)};
    if (!rule_set) {
        return ValidationResult::kUnknownProtocolRuleSet;
    }
    ExecutionProcessor processor{block, *rule_set, state, chain_config};
    processor.evm().analysis_cache = &analysis_cache;
    processor.evm().state_pool = &state_pool;
    return processor.execute_and_write_block(receipts);
}

/**
 * @brief Execute a given block, write resulting changes into the state and return the transaction receipts.
 * @precondition validate_block_header & pre_validate_block_body must return kOk; transaction senders must be already populated.
 * @warning This method does not verify state root; pre-Byzantium receipt root isn't validated either.
 * @warning For better performance use ExecutionProcessor directly and set EVM state_pool and analysis_cache.
 * @param block The block to execute.
 * @param state The chain state at the beginning of the block.
 * @param chain_config The configuration parameters for the chain.
 * @param receipts The transaction receipts produced by block execution.
 */
[[nodiscard]] inline ValidationResult execute_block(const Block& block, State& state, const ChainConfig& chain_config,
                                                    std::vector<Receipt>& receipts) noexcept {
    const auto rule_set{protocol::rule_set_factory(chain_config)};
    if (!rule_set) {
        return ValidationResult::kUnknownProtocolRuleSet;
    }
    ExecutionProcessor processor{block, *rule_set, state, chain_config};
    return processor.execute_and_write_block(receipts);
}

/**
 * @brief Execute a given block and write resulting changes into the state.
 * @precondition validate_block_header & pre_validate_block_body must return kOk; transaction senders must be already populated.
 * @warning This method does not verify state root; pre-Byzantium receipt root isn't validated either.
 * @warning For better performance use ExecutionProcessor directly and set EVM state_pool and analysis_cache.
 * @param block The block to execute.
 * @param state The chain state at the beginning of the block.
 * @param chain_config The configuration parameters for the chain.
 */
[[nodiscard]] inline ValidationResult execute_block(const Block& block, State& state,
                                                    const ChainConfig& chain_config) noexcept {
    std::vector<Receipt> receipts;
    return execute_block(block, state, chain_config, receipts);
}

}  // namespace silkworm
