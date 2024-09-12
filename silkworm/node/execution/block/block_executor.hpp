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

#pragma once

#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/buffer.hpp>

namespace silkworm::execution::block {

class BlockExecutor {
  public:
    static constexpr size_t kDefaultAnalysisCacheSize{5'000};

    BlockExecutor(const ChainConfig* chain_config, bool write_receipts, bool write_call_traces, bool write_change_sets);

    ValidationResult execute_single(const Block& block, db::Buffer& state_buffer, AnalysisCache& analysis_cache, ObjectPool<evmone::ExecutionState>& state_pool);

  private:
    const ChainConfig* chain_config_;
    protocol::RuleSetPtr protocol_rule_set_;
    bool write_receipts_;
    bool write_call_traces_;
    bool write_change_sets_;
};

}  // namespace silkworm::execution::block