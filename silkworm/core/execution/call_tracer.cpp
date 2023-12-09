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
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>

#include <silkworm/core/types/address.hpp>

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

void CallTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t /*gas*/,
                                      const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept {
    const auto op_code = state.original_code[pc];
    if (op_code == evmc_opcode::OP_CREATE) {
        const uint64_t nonce{intra_block_state.get_nonce(state.msg->recipient)};
        const auto& contract_address{create_address(state.msg->recipient, nonce)};

        traces_.senders.insert(state.msg->recipient);
        traces_.recipients.insert(contract_address);
    } else if (op_code == evmc_opcode::OP_CREATE2) {
        SILKWORM_ASSERT(stack_height >= 4);
        const auto init_code_offset = static_cast<size_t>(stack_top[-1]);
        const auto init_code_size = static_cast<size_t>(stack_top[-2]);
        const evmc::bytes32 salt2{intx::be::store<evmc::bytes32>(stack_top[-3])};
        SILKWORM_ASSERT(init_code_offset < state.memory.size());
        auto init_code_hash{
            init_code_size > 0 ? ethash::keccak256(&state.memory.data()[init_code_offset], init_code_size) : ethash_hash256{}};
        const auto& contract_address{create2_address(state.msg->recipient, salt2, init_code_hash.bytes)};

        traces_.senders.insert(state.msg->recipient);
        traces_.recipients.insert(contract_address);
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
