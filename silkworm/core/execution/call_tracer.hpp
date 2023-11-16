/*
   Copyright 2023 The Silkworm Authors

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

  private:
    CallTraces& traces_;
};

}  // namespace silkworm
