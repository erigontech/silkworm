// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/buffer.hpp>

namespace silkworm::execution::block {

class BlockExecutor {
  public:
    static constexpr size_t kDefaultAnalysisCacheSize{5'000};

    BlockExecutor(const ChainConfig* chain_config, bool write_receipts, bool write_call_traces, bool write_change_sets);

    ValidationResult execute_single(const Block& block, db::Buffer& state_buffer, AnalysisCache& analysis_cache);

  private:
    const ChainConfig* chain_config_;
    protocol::RuleSetPtr protocol_rule_set_;
    bool write_receipts_;
    bool write_call_traces_;
    bool write_change_sets_;
};

}  // namespace silkworm::execution::block
