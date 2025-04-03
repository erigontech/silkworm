// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include <silkworm/core/execution/evm.hpp>
#pragma GCC diagnostic pop

#include <silkworm/core/types/call_traces.hpp>

namespace silkworm {

//! CallTracer collects source and destination account addresses touched during execution by tracing EVM calls.
class CallTracer : public EvmTracer {
  public:
    explicit CallTracer(CallTraces& traces) : traces_{traces} {}

    CallTracer(const CallTracer&) = delete;
    CallTracer& operator=(const CallTracer&) = delete;

    void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept override;
    void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                              const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept override;
    void on_self_destruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;
    void on_block_end(const silkworm::Block& block) noexcept override;

  private:
    CallTraces& traces_;
};

}  // namespace silkworm
