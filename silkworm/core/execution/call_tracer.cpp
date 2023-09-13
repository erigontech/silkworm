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

#include "call_tracer.hpp"

#include <evmc/hex.hpp>
#include <evmone/execution_state.hpp>

namespace silkworm {

void CallTracer::on_execution_start(evmc_revision /*rev*/, const evmc_message& msg, evmone::bytes_view /*code*/) noexcept {
    traces_.senders.emplace(msg.sender);
    traces_.recipients.emplace(msg.recipient);
}

}  // namespace silkworm
