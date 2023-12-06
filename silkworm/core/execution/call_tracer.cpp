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
    if (msg.kind == EVMC_CALLCODE) {
        traces_.senders.insert(msg.sender);
        traces_.recipients.insert(msg.code_address);
    } else if (msg.kind == EVMC_DELEGATECALL) {
        traces_.senders.insert(msg.recipient);
        traces_.recipients.insert(msg.code_address);
    } else {
        traces_.senders.insert(msg.sender);
        traces_.recipients.insert(msg.recipient);
    }
}

void CallTracer::on_self_destruct(const evmc::address& address, const evmc::address& beneficiary) noexcept {
    traces_.senders.insert(address);
    traces_.recipients.insert(beneficiary);
}

void CallTracer::on_block_end(const silkworm::Block& block) noexcept {
    traces_.recipients.insert(block.header.beneficiary);
    for (const auto& ommer : block.ommers) {
        traces_.recipients.insert(ommer.beneficiary);
    }
}

}  // namespace silkworm
