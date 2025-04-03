// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    ExecutionProcessor processor{block, *rule_set, state, chain_config, true};

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
