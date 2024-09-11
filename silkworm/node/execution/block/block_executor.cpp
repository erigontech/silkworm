/*
   Copyright 2024 The Silkworm Authors

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

#include <tuple>

#include <silkworm/core/execution/call_tracer.hpp>
#include <silkworm/core/execution/processor.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/execution/block/block_executor.hpp>

namespace silkworm::execution::block {

using namespace std::chrono_literals;

BlockExecutor::BlockExecutor(const ChainConfig* chain_config, bool write_receipts, bool write_call_traces, bool write_change_sets, size_t max_batch_size, std::optional<CustomerLogger> custom_logger)
    : chain_config_{chain_config},
      protocol_rule_set_{protocol::rule_set_factory(*chain_config_)},
      write_receipts_{write_receipts},
      write_call_traces_{write_call_traces},
      write_change_sets_{write_change_sets},
      progress_{.start_time = std::chrono::steady_clock::now()},
      log_time_{progress_.start_time + 20s},
      max_batch_size_{max_batch_size},
      custom_logger_{custom_logger} {}

ValidationResult BlockExecutor::execute_single(const Block& block, db::Buffer& state_buffer, AnalysisCache& analysis_cache, ObjectPool<evmone::ExecutionState>& state_pool) {
    ExecutionProcessor processor{block, *protocol_rule_set_, state_buffer, *chain_config_};
    processor.evm().analysis_cache = &analysis_cache;
    processor.evm().state_pool = &state_pool;

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

    progress_.processed_blocks++;
    progress_.processed_transactions += block.transactions.size();
    progress_.processed_gas += block.header.gas_used;

    const auto now{std::chrono::steady_clock::now()};
    if (log_time_ <= now && custom_logger_) {
        progress_.batch_progress_perc = static_cast<float>(state_buffer.current_batch_state_size()) / static_cast<float>(max_batch_size_);
        progress_.end_time = now;
        auto& custom_logger = *custom_logger_;
        log::Info{"[4/12 Execution] Executed blocks",  // NOLINT(*-unused-raii)
                  custom_logger(progress_, block.header.number)};
        log_time_ = now + 20s;
    }

    return ValidationResult::kOk;
}
}  // namespace silkworm::execution::block
