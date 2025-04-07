// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call_tracer.hpp"

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/baseline_instruction_table.hpp>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>

#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/types/address.hpp>

using namespace evmone;
using namespace evmone::baseline;

// The following functions have been temporarily copied from evmone because not exported or need changes.
// We need to ask evmone for it to be exported/modified or an extended tracing interface (e.g. on_instruction_end?).
namespace {
//! Copy of evmone::check_requirements: not exported
template <Opcode Op>
evmc_status_code check_requirements(
    const CostTable& cost_table,
    int64_t& gas_left,
    const uint256* stack_top,
    const uint256* stack_bottom) noexcept {
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
        static constexpr int kMinOffset = instr::traits[Op].stack_height_required - 1;
        if (INTX_UNLIKELY(stack_top <= stack_bottom + kMinOffset))
            return EVMC_STACK_UNDERFLOW;
    }

    if (INTX_UNLIKELY((gas_left -= gas_cost) < 0)) {  // NOLINT(*-assignment-in-if-condition)
        return EVMC_OUT_OF_GAS;
    }

    return EVMC_SUCCESS;
}

//! Adaptation of evmone::grow_memory: we need just to check gas requirements w/o growing memory
int64_t check_memory_gas(int64_t gas_left, Memory& memory, uint64_t new_size) noexcept {
    const auto new_words = static_cast<int64_t>(silkworm::num_words(new_size));
    const auto current_words = static_cast<int64_t>(memory.size() / word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    gas_left -= cost;
    // We *must* avoid growing memory up here otherwise the subsequent gas costs change and block execution fails
    // (e.g. block 2'310'926 on Sepolia)
    /*if (gas_left >= 0) [[likely]]
        memory.grow(static_cast<size_t>(new_words * word_size));*/
    return gas_left;
}

//! Adaptation of evmone::check_memory: we need just to check gas requirements w/o growing memory
bool check_memory_gas(int64_t& gas_left, Memory& memory, const uint256& offset, uint64_t size) noexcept {
    if (((offset[3] | offset[2] | offset[1]) != 0) || (offset[0] > max_buffer_size))
        return false;

    // There is "branch-less" variant of this using | instead of ||, but benchmarks difference
    // is within noise. This should be decided when moving the implementation to intx.
    const auto new_size = static_cast<uint64_t>(offset) + size;
    if (new_size > memory.size())
        gas_left = check_memory_gas(gas_left, memory, new_size);

    return gas_left >= 0;  // Always true for no-grow case.
}

//! Adaptation of evmone::check_memory: we need just to check gas requirements w/o growing memory
inline bool check_memory_gas(int64_t& gas_left, Memory& memory, const uint256& offset, const uint256& size) noexcept {
    if (size == 0)  // Copy of size 0 is always valid (even if offset is huge).
        return true;

    // This check has 3 same word checks with the check above.
    // However, compilers do decent although not perfect job unifying common instructions.
    if (((size[3] | size[2] | size[1]) != 0) || (size[0] > max_buffer_size))
        return false;

    return check_memory_gas(gas_left, memory, offset, static_cast<uint64_t>(size));
}
}  // namespace

template <Opcode Op>
inline evmc_status_code check_preconditions(const intx::uint256* stack_top, int stack_height, int64_t gas,
                                            const evmone::ExecutionState& state) noexcept {
    const auto& cost_table{get_baseline_cost_table(state.rev, state.analysis.baseline->eof_header().version)};
    return check_requirements<Op>(cost_table, gas, stack_top, stack_top - stack_height);
}

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

template <Opcode Op>
void on_create_start(const intx::uint256* stack_top, int stack_height, int64_t gas,
                     const evmone::ExecutionState& state, const IntraBlockState& intra_block_state, CallTraces& traces) {
    if (const auto status{check_preconditions<Op>(stack_top, stack_height, gas, state)}; status != EVMC_SUCCESS) {
        return;  // Early failure in pre-execution checks, do not trace anything for compatibility w/ Erigon
    }
    if (stack_height < 3 + 1 * (Op == Opcode::OP_CREATE2)) {
        return;  // Invariant break for current implementation of OP_CREATE or OP_CREATE2, let's handle gracefully.
    }
    StackTop stack{const_cast<intx::uint256*>(stack_top)};  // NOLINT(cppcoreguidelines-pro-type-const-cast)
    const auto init_code_offset_u256 = stack[1];
    const auto init_code_size_u256 = stack[2];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    if (!check_memory_gas(gas, const_cast<evmone::Memory&>(state.memory), init_code_offset_u256, init_code_size_u256)) {
        return;  // The execution has run of out-of-gas during contract deployment, do not trace anything
    }
    const auto init_code_offset = static_cast<size_t>(init_code_offset_u256);
    if (init_code_offset >= state.memory.size()) {
        return;  // Invariant break for current implementation of OP_CREATE2, let's handle gracefully.
    }
    const auto init_code_size = static_cast<size_t>(init_code_size_u256);
    if (init_code_size >= state.memory.size() - init_code_offset) {
        return;  // Invariant break for current implementation of OP_CREATE2, let's handle gracefully.
    }
    if (state.rev >= EVMC_SHANGHAI && init_code_size > 0xC000) {
        return;  // The execution has run of out-of-gas during contract deployment, do not trace anything
    }
    const auto init_code_word_cost = 6 * (Op == Opcode::OP_CREATE2) + 2 * (state.rev >= EVMC_SHANGHAI);
    const auto init_code_cost = static_cast<int64_t>(silkworm::num_words(init_code_size)) * init_code_word_cost;
    if (gas - init_code_cost < 0) {
        return;  // The execution has run of out-of-gas during contract deployment, do not trace anything
    }

    evmc::address contract_address;
    if (Op == Opcode::OP_CREATE) {
        const uint64_t nonce{intra_block_state.get_nonce(state.msg->recipient)};
        contract_address = create_address(state.msg->recipient, nonce);
    } else {
        SILKWORM_ASSERT(Op == Opcode::OP_CREATE2);
        const evmc::bytes32 salt2{intx::be::store<evmc::bytes32>(stack[3])};
        auto init_code_hash{
            init_code_size > 0 ? ethash::keccak256(&state.memory.data()[init_code_offset], init_code_size) : ethash_hash256{}};
        contract_address = create2_address(state.msg->recipient, salt2, init_code_hash.bytes);
    }
    traces.senders.insert(state.msg->recipient);
    traces.recipients.insert(contract_address);
}

void CallTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height, int64_t gas,
                                      const evmone::ExecutionState& state, const IntraBlockState& intra_block_state) noexcept {
    const auto op_code = state.original_code[pc];
    if (op_code == evmc_opcode::OP_CREATE) {
        on_create_start<Opcode::OP_CREATE>(stack_top, stack_height, gas, state, intra_block_state, traces_);
    } else if (op_code == evmc_opcode::OP_CREATE2) {
        on_create_start<Opcode::OP_CREATE2>(stack_top, stack_height, gas, state, intra_block_state, traces_);
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
