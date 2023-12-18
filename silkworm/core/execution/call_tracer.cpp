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
#include <evmone/baseline_instruction_table.hpp>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>

#include <silkworm/core/types/address.hpp>

using namespace evmone;
using namespace evmone::baseline;

// The following check_requirements function has been temporarily copied from evmone because it is not exported.
// We need to ask evmone for it to be exported or for a tracing interface extension (e.g. on_instruction_end?).
namespace {
template <Opcode Op>
[[deprecated("Temporary fix, await tracing interface extension")]] inline evmc_status_code check_requirements(const CostTable& cost_table, int64_t& gas_left,
                                                                                                              const uint256* stack_top, const uint256* stack_bottom) noexcept {
    static_assert(
        !instr::has_const_gas_cost(Op) || instr::gas_costs[EVMC_FRONTIER][Op] != instr::undefined,
        "undefined instructions must not be handled by check_requirements()");

    auto gas_cost = instr::gas_costs[EVMC_FRONTIER][Op];  // Init assuming const cost.
    if constexpr (!instr::has_const_gas_cost(Op)) {
        gas_cost = cost_table[Op];  // If not, load the cost from the table.

        // Negative cost marks an undefined instruction.
        // This check must be first to produce correct error code.
        if (INTX_UNLIKELY(gas_cost < 0))
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    // Check stack requirements first. This is order is not required,
    // but it is nicer because complete gas check may need to inspect operands.
    if constexpr (instr::traits[Op].stack_height_change > 0) {
        static_assert(instr::traits[Op].stack_height_change == 1,
                      "unexpected instruction with multiple results");
        if (INTX_UNLIKELY(stack_top == stack_bottom + StackSpace::limit))
            return EVMC_STACK_OVERFLOW;
    }
    if constexpr (instr::traits[Op].stack_height_required > 0) {
        // Check stack underflow using pointer comparison <= (better optimization).
        static constexpr auto min_offset = instr::traits[Op].stack_height_required - 1;
        if (INTX_UNLIKELY(stack_top <= stack_bottom + min_offset))
            return EVMC_STACK_UNDERFLOW;
    }

    if (INTX_UNLIKELY((gas_left -= gas_cost) < 0)) {
        return EVMC_OUT_OF_GAS;
    }

    return EVMC_SUCCESS;
}
}  // namespace

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

void CallTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                                      const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept {
    const auto op_code = state.original_code[pc];
    if (op_code == evmc_opcode::OP_CREATE) {
        const auto& cost_table{get_baseline_cost_table(state.rev, state.analysis.baseline->eof_header.version)};
        if (const auto status{check_requirements<Opcode::OP_CREATE>(cost_table, gas, stack_top, stack_top - stack_height)}; status != EVMC_SUCCESS) {
            return;  // Early failure in pre-execution checks, do not trace anything for compatibility w/ Erigon
        }
        const uint64_t nonce{intra_block_state.get_nonce(state.msg->recipient)};
        const auto& contract_address{create_address(state.msg->recipient, nonce)};

        traces_.senders.insert(state.msg->recipient);
        traces_.recipients.insert(contract_address);
    } else if (op_code == evmc_opcode::OP_CREATE2) {
        const auto& cost_table{get_baseline_cost_table(state.rev, state.analysis.baseline->eof_header.version)};
        if (const auto status{check_requirements<Opcode::OP_CREATE2>(cost_table, gas, stack_top, stack_top - stack_height)}; status != EVMC_SUCCESS) {
            return;  // Early failure in pre-execution checks, do not trace anything for compatibility w/ Erigon
        }
        if (stack_height < 4) {
            return;  // Invariant break for current implementation of OP_CREATE2, let's handle this gracefully.
        }
        const auto init_code_offset = static_cast<size_t>(stack_top[-1]);
        if (init_code_offset >= state.memory.size()) {
            return;  // Invariant break for current implementation of OP_CREATE2, let's handle this gracefully.
        }
        const auto init_code_size = static_cast<size_t>(stack_top[-2]);
        const evmc::bytes32 salt2{intx::be::store<evmc::bytes32>(stack_top[-3])};
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
