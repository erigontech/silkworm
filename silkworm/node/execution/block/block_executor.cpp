// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <tuple>

#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/execution/processor.hpp>
#include <silkworm/node/execution/block/block_executor.hpp>

namespace silkworm::execution::block {

using namespace std::chrono_literals;

BlockExecutor::BlockExecutor(const ChainConfig* chain_config, bool write_receipts, bool write_call_traces, bool write_change_sets)
    : chain_config_{chain_config},
      protocol_rule_set_{protocol::rule_set_factory(*chain_config_)},
      write_receipts_{write_receipts},
      write_call_traces_{write_call_traces},
      write_change_sets_{write_change_sets} {}

ValidationResult BlockExecutor::execute_single(const Block& block, db::Buffer& state_buffer, AnalysisCache& analysis_cache) {
    ExecutionProcessor processor{block, *protocol_rule_set_, state_buffer, *chain_config_, true};
    processor.evm().analysis_cache = &analysis_cache;

    CallTraces traces;
    CallTracer tracer{traces};
    if (write_call_traces_) {
        processor.evm().add_tracer(tracer);
    }

    std::vector<Receipt> receipts;
    if (const ValidationResult res = processor.execute_block(receipts); res != ValidationResult::kOk) {
        return res;
    }

    processor.flush_state();

    if (write_receipts_) {
        state_buffer.insert_receipts(block.header.number, receipts);
    }
    if (write_call_traces_) {
        state_buffer.insert_call_traces(block.header.number, traces);
    }

    state_buffer.write_history_to_db(write_change_sets_);

    return ValidationResult::kOk;
}

}  // namespace silkworm::execution::block
