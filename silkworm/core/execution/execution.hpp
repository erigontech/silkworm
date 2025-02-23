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
#include <silkworm/core/types/call_traces.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

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
inline ValidationResult execute_block(
    const Block& block,
    State& state,
    const ChainConfig& chain_config,
    std::vector<Receipt>& receipts) noexcept {
    const auto rule_set{protocol::rule_set_factory(chain_config)};
    if (!rule_set) {
        return ValidationResult::kUnknownProtocolRuleSet;
    }
    ExecutionProcessor processor{block, *rule_set, state, chain_config, /*evm1_v2=*/true};

    if (const ValidationResult res = processor.execute_block(receipts); res != ValidationResult::kOk) {
        return res;
    }

    processor.flush_state();

    return ValidationResult::kOk;
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
inline ValidationResult execute_block(
    const Block& block,
    State& state,
    const ChainConfig& chain_config) noexcept {
    std::vector<Receipt> receipts;
    return execute_block(block, state, chain_config, receipts);
}

}  // namespace silkworm
