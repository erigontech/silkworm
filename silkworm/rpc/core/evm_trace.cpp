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

#include "evm_trace.hpp"

#include <algorithm>
#include <memory>
#include <set>
#include <stack>
#include <string>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/precompile.hpp>
#include <silkworm/core/protocol/ethash_rule_set.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/rawdb/chain.hpp>
#include <silkworm/rpc/json/call.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::trace {

void from_json(const nlohmann::json& json, TraceConfig& tc) {
    std::vector<std::string> config;
    json.get_to(config);

    tc.vm_trace = std::find(config.begin(), config.end(), "vmTrace") != config.end();
    tc.trace = std::find(config.begin(), config.end(), "trace") != config.end();
    tc.state_diff = std::find(config.begin(), config.end(), "stateDiff") != config.end();
}

std::ostream& operator<<(std::ostream& out, const TraceConfig& tc) {
    out << "vmTrace: " << std::boolalpha << tc.vm_trace;
    out << " Trace: " << std::boolalpha << tc.trace;
    out << " stateDiff: " << std::boolalpha << tc.state_diff;

    return out;
}

std::ostream& operator<<(std::ostream& out, const TraceFilter& tf) {
    out << "from_block: " << std::dec << tf.from_block;
    out << ", to_block: " << std::dec << tf.to_block;
    if (!tf.from_addresses.empty()) {
        out << ", from_addresses: [";
        std::copy(tf.from_addresses.begin(), tf.from_addresses.end(), std::ostream_iterator<evmc::address>(out, ", "));
        out << "]";
    }
    if (!tf.to_addresses.empty()) {
        out << ", to_addresses: [";
        std::copy(tf.to_addresses.begin(), tf.to_addresses.end(), std::ostream_iterator<evmc::address>(out, ", "));
        out << "]";
    }
    if (tf.mode) {
        out << ", mode: " << tf.mode.value();
    }
    out << ", after: " << std::dec << tf.after;
    out << ", count: " << std::dec << tf.count;

    return out;
}

void from_json(const nlohmann::json& json, TraceCall& tc) {
    tc.call = json.at(0);
    tc.trace_config = json.at(1);
}

void from_json(const nlohmann::json& json, TraceFilter& tf) {
    if (json.contains("fromBlock")) {
        tf.from_block = json["fromBlock"];
    }
    if (json.contains("toBlock")) {
        tf.to_block = json["toBlock"];
    }
    if (json.contains("fromAddress")) {
        tf.from_addresses = json["fromAddress"];
    }
    if (json.contains("toAddress")) {
        tf.to_addresses = json["toAddress"];
    }
    if (json.contains("mode")) {
        tf.mode = json["mode"];
    }
    if (json.contains("after")) {
        tf.after = json["after"];
    }
    if (json.contains("count")) {
        tf.count = json["count"];
    }
}

void to_json(nlohmann::json& json, const VmTrace& vm_trace) {
    json["code"] = vm_trace.code;
    json["ops"] = vm_trace.ops;
}

void to_json(nlohmann::json& json, const TraceOp& trace_op) {
    json["cost"] = trace_op.gas_cost;
    json["ex"] = trace_op.trace_ex;
    json["idx"] = trace_op.idx;
    json["op"] = trace_op.op_name;
    json["pc"] = trace_op.pc;
    if (trace_op.sub) {
        json["sub"] = *trace_op.sub;
    } else {
        json["sub"] = nlohmann::json::value_t::null;
    }
}

void to_json(nlohmann::json& json, const TraceEx& trace_ex) {
    if (trace_ex.memory) {
        const auto& memory = trace_ex.memory.value();
        json["mem"] = memory;
    } else {
        json["mem"] = nlohmann::json::value_t::null;
    }

    json["push"] = trace_ex.stack;
    if (trace_ex.storage) {
        const auto& storage = trace_ex.storage.value();
        json["store"] = storage;
    } else {
        json["store"] = nlohmann::json::value_t::null;
    }
    json["used"] = trace_ex.used;
}

void to_json(nlohmann::json& json, const TraceMemory& trace_memory) {
    json = {
        {"data", trace_memory.data},
        {"off", trace_memory.offset}};
}

void to_json(nlohmann::json& json, const TraceStorage& trace_storage) {
    json = {
        {"key", trace_storage.key},
        {"val", trace_storage.value}};
}

void to_json(nlohmann::json& json, const TraceAction& action) {
    if (action.call_type) {
        json["callType"] = action.call_type.value();
    }
    json["from"] = action.from;
    if (action.to) {
        json["to"] = action.to.value();
    }
    std::ostringstream ss;
    ss << "0x" << std::hex << action.gas;
    json["gas"] = ss.str();
    if (action.input) {
        json["input"] = "0x" + silkworm::to_hex(action.input.value());
    }
    if (action.init) {
        json["init"] = "0x" + silkworm::to_hex(action.init.value());
    }
    json["value"] = to_quantity(action.value);
}

void to_json(nlohmann::json& json, const RewardAction& action) {
    json["author"] = action.author;
    json["rewardType"] = action.reward_type;
    json["value"] = to_quantity(action.value);
}

void to_json(nlohmann::json& json, const TraceResult& trace_result) {
    if (trace_result.address) {
        json["address"] = trace_result.address.value();
    }
    if (trace_result.code) {
        json["code"] = "0x" + silkworm::to_hex(trace_result.code.value());
    }
    if (trace_result.output) {
        json["output"] = "0x" + silkworm::to_hex(trace_result.output.value());
    }
    std::ostringstream ss;
    ss << "0x" << std::hex << trace_result.gas_used;
    json["gasUsed"] = ss.str();
}

void to_json(nlohmann::json& json, const Trace& trace) {
    if (std::holds_alternative<TraceAction>(trace.action)) {
        json["action"] = std::get<TraceAction>(trace.action);
    } else if (std::holds_alternative<RewardAction>(trace.action)) {
        json["action"] = std::get<RewardAction>(trace.action);
    }
    if (trace.trace_result) {
        json["result"] = trace.trace_result.value();
    } else {
        json["result"] = nlohmann::json::value_t::null;
    }
    json["subtraces"] = trace.sub_traces;
    json["traceAddress"] = trace.trace_address;
    if (trace.error) {
        json["error"] = trace.error.value();
    }
    json["type"] = trace.type;
    if (trace.block_hash) {
        json["blockHash"] = trace.block_hash.value();
    }
    if (trace.block_number) {
        json["blockNumber"] = trace.block_number.value();
    }
    if (trace.transaction_hash) {
        json["transactionHash"] = trace.transaction_hash.value();
    }
    if (trace.transaction_position) {
        json["transactionPosition"] = trace.transaction_position.value();
    }
}

void to_json(nlohmann::json& json, const DiffValue& dv) {
    if (dv.from && dv.to) {
        json["*"] = {
            {"from", dv.from.value()},
            {"to", dv.to.value()}};
    } else if (dv.from) {
        json["-"] = dv.from.value();
    } else if (dv.to) {
        json["+"] = dv.to.value();
    } else {
        json = "=";
    }
}

void to_json(nlohmann::json& json, const StateDiffEntry& state_diff) {
    json["balance"] = state_diff.balance;
    json["code"] = state_diff.code;
    json["nonce"] = state_diff.nonce;
    json["storage"] = state_diff.storage;
}

void to_json(nlohmann::json& json, const TraceCallTraces& result) {
    json["output"] = result.output;
    if (result.state_diff) {
        json["stateDiff"] = result.state_diff.value();
    } else {
        json["stateDiff"] = nlohmann::json::value_t::null;
    }
    json["trace"] = result.trace;
    if (result.vm_trace) {
        json["vmTrace"] = result.vm_trace.value();
    } else {
        json["vmTrace"] = nlohmann::json::value_t::null;
    }
    if (result.transaction_hash) {
        json["transactionHash"] = result.transaction_hash.value();
    }
}

void to_json(nlohmann::json& json, const TraceCallResult& result) {
    to_json(json, result.traces);
}

void to_json(nlohmann::json& json, const TraceManyCallResult& result) {
    json = nlohmann::json::array();
    for (const auto& trace : result.traces) {
        json.push_back(nlohmann::json::value_t::null);
        to_json(json.at(json.size() - 1), trace);
    }
}

void to_json(nlohmann::json& json, const TraceDeployResult& result) {
    json["hash"] = result.transaction_hash.value();
    json["creator"] = result.contract_creator.value();
}

void to_json(nlohmann::json& json, const TraceEntry& trace_entry) {
    json["type"] = trace_entry.type;
    json["depth"] = trace_entry.depth;
    json["from"] = trace_entry.from;
    json["to"] = trace_entry.to;
    if (trace_entry.value.empty()) {
        json["value"] = nullptr;
    } else {
        json["value"] = trace_entry.value;
    }
    json["input"] = trace_entry.input;
}

void to_json(nlohmann::json& json, const InternalOperation& trace_operation) {
    json["type"] = trace_operation.type;
    json["from"] = trace_operation.from;
    json["to"] = trace_operation.to;
    if (trace_operation.value.empty()) {
        json["value"] = nullptr;
    } else {
        json["value"] = trace_operation.value;
    }
}

int get_stack_count(std::uint8_t op_code) {
    int count{0};
    switch (op_code) {
        case evmc_opcode::OP_PUSH1:
        case evmc_opcode::OP_PUSH2:
        case evmc_opcode::OP_PUSH3:
        case evmc_opcode::OP_PUSH4:
        case evmc_opcode::OP_PUSH5:
        case evmc_opcode::OP_PUSH6:
        case evmc_opcode::OP_PUSH7:
        case evmc_opcode::OP_PUSH8:
        case evmc_opcode::OP_PUSH9:
        case evmc_opcode::OP_PUSH10:
        case evmc_opcode::OP_PUSH11:
        case evmc_opcode::OP_PUSH12:
        case evmc_opcode::OP_PUSH13:
        case evmc_opcode::OP_PUSH14:
        case evmc_opcode::OP_PUSH15:
        case evmc_opcode::OP_PUSH16:
        case evmc_opcode::OP_PUSH17:
        case evmc_opcode::OP_PUSH18:
        case evmc_opcode::OP_PUSH19:
        case evmc_opcode::OP_PUSH20:
        case evmc_opcode::OP_PUSH21:
        case evmc_opcode::OP_PUSH22:
        case evmc_opcode::OP_PUSH23:
        case evmc_opcode::OP_PUSH24:
        case evmc_opcode::OP_PUSH25:
        case evmc_opcode::OP_PUSH26:
        case evmc_opcode::OP_PUSH27:
        case evmc_opcode::OP_PUSH28:
        case evmc_opcode::OP_PUSH29:
        case evmc_opcode::OP_PUSH30:
        case evmc_opcode::OP_PUSH31:
        case evmc_opcode::OP_PUSH32:
            count = 1;
            break;
        case evmc_opcode::OP_SWAP1:
        case evmc_opcode::OP_SWAP2:
        case evmc_opcode::OP_SWAP3:
        case evmc_opcode::OP_SWAP4:
        case evmc_opcode::OP_SWAP5:
        case evmc_opcode::OP_SWAP6:
        case evmc_opcode::OP_SWAP7:
        case evmc_opcode::OP_SWAP8:
        case evmc_opcode::OP_SWAP9:
        case evmc_opcode::OP_SWAP10:
        case evmc_opcode::OP_SWAP11:
        case evmc_opcode::OP_SWAP12:
        case evmc_opcode::OP_SWAP13:
        case evmc_opcode::OP_SWAP14:
        case evmc_opcode::OP_SWAP15:
        case evmc_opcode::OP_SWAP16:
            count = op_code - evmc_opcode::OP_SWAP1 + 2;
            break;
        case evmc_opcode::OP_DUP1:
        case evmc_opcode::OP_DUP2:
        case evmc_opcode::OP_DUP3:
        case evmc_opcode::OP_DUP4:
        case evmc_opcode::OP_DUP5:
        case evmc_opcode::OP_DUP6:
        case evmc_opcode::OP_DUP7:
        case evmc_opcode::OP_DUP8:
        case evmc_opcode::OP_DUP9:
        case evmc_opcode::OP_DUP10:
        case evmc_opcode::OP_DUP11:
        case evmc_opcode::OP_DUP12:
        case evmc_opcode::OP_DUP13:
        case evmc_opcode::OP_DUP14:
        case evmc_opcode::OP_DUP15:
        case evmc_opcode::OP_DUP16:
            count = op_code - evmc_opcode::OP_DUP1 + 2;
            break;
        case evmc_opcode::OP_CALLDATALOAD:
        case evmc_opcode::OP_SLOAD:
        case evmc_opcode::OP_MLOAD:
        case evmc_opcode::OP_CALLDATASIZE:
        case evmc_opcode::OP_LT:
        case evmc_opcode::OP_GT:
        case evmc_opcode::OP_DIV:
        case evmc_opcode::OP_SDIV:
        case evmc_opcode::OP_SAR:
        case evmc_opcode::OP_AND:
        case evmc_opcode::OP_EQ:
        case evmc_opcode::OP_CALLVALUE:
        case evmc_opcode::OP_ISZERO:
        case evmc_opcode::OP_ADD:
        case evmc_opcode::OP_EXP:
        case evmc_opcode::OP_CALLER:
        case evmc_opcode::OP_KECCAK256:
        case evmc_opcode::OP_SUB:
        case evmc_opcode::OP_ADDRESS:
        case evmc_opcode::OP_GAS:
        case evmc_opcode::OP_MUL:
        case evmc_opcode::OP_RETURNDATASIZE:
        case evmc_opcode::OP_NOT:
        case evmc_opcode::OP_SHR:
        case evmc_opcode::OP_SHL:
        case evmc_opcode::OP_EXTCODESIZE:
        case evmc_opcode::OP_SLT:
        case evmc_opcode::OP_OR:
        case evmc_opcode::OP_NUMBER:
        case evmc_opcode::OP_PC:
        case evmc_opcode::OP_TIMESTAMP:
        case evmc_opcode::OP_BALANCE:
        case evmc_opcode::OP_SELFBALANCE:
        case evmc_opcode::OP_MULMOD:
        case evmc_opcode::OP_ADDMOD:
        case evmc_opcode::OP_BASEFEE:
        case evmc_opcode::OP_BLOCKHASH:
        case evmc_opcode::OP_BYTE:
        case evmc_opcode::OP_XOR:
        case evmc_opcode::OP_ORIGIN:
        case evmc_opcode::OP_CODESIZE:
        case evmc_opcode::OP_MOD:
        case evmc_opcode::OP_SIGNEXTEND:
        case evmc_opcode::OP_GASLIMIT:
        case evmc_opcode::OP_PREVRANDAO:
        case evmc_opcode::OP_SGT:
        case evmc_opcode::OP_GASPRICE:
        case evmc_opcode::OP_MSIZE:
        case evmc_opcode::OP_EXTCODEHASH:
        case evmc_opcode::OP_STATICCALL:
        case evmc_opcode::OP_DELEGATECALL:
        case evmc_opcode::OP_CALL:
        case evmc_opcode::OP_CALLCODE:
        case evmc_opcode::OP_CREATE:
        case evmc_opcode::OP_CREATE2:
        case evmc_opcode::OP_COINBASE:
        case evmc_opcode::OP_CHAINID:
        case evmc_opcode::OP_SMOD:
            count = 1;
            break;
        default:
            count = 0;
            break;
    }

    return count;
}

void copy_stack(std::uint8_t op_code, const evmone::uint256* stack, std::vector<std::string>& trace_stack) {
    const int top = get_stack_count(op_code);
    trace_stack.reserve(top > 0 ? static_cast<std::size_t>(top) : 0);
    for (int i = top - 1; i >= 0; i--) {
        const auto str = intx::to_string(stack[-i], 16);
        trace_stack.push_back("0x" + intx::to_string(stack[-i], 16));
    }
}

void copy_memory(const evmone::Memory& memory, std::optional<TraceMemory>& trace_memory) {
    if (trace_memory) {
        TraceMemory& tm = trace_memory.value();
        if (tm.len == 0) {
            trace_memory.reset();
            return;
        }
        tm.data = "0x";
        const auto data = memory.data();
        const auto start = tm.offset;
        for (uint64_t idx{0}; idx < tm.len; idx++) {
            std::string entry{evmc::hex({data + start + idx, 1})};
            tm.data.append(entry);
        }
    }
}

void copy_store(std::uint8_t op_code, const evmone::uint256* stack, std::optional<TraceStorage>& trace_storage) {
    if (op_code == evmc_opcode::OP_SSTORE) {
        trace_storage = TraceStorage{"0x" + intx::to_string(stack[0], 16), "0x" + intx::to_string(stack[-1], 16)};
    }
}

void copy_memory_offset_len(std::uint8_t op_code, const evmone::uint256* stack, std::optional<TraceMemory>& trace_memory) {
    switch (op_code) {
        case evmc_opcode::OP_MSTORE:
        case evmc_opcode::OP_MLOAD:
            trace_memory = TraceMemory{stack[0][0], 32};
            break;
        case evmc_opcode::OP_MSTORE8:
            trace_memory = TraceMemory{stack[0][0], 1};
            break;
        case evmc_opcode::OP_RETURNDATACOPY:
        case evmc_opcode::OP_CALLDATACOPY:
        case evmc_opcode::OP_CODECOPY:
            trace_memory = TraceMemory{stack[0][0], stack[-2][0]};
            break;
        case evmc_opcode::OP_STATICCALL:
        case evmc_opcode::OP_DELEGATECALL:
            trace_memory = TraceMemory{stack[-4][0], stack[-5][0]};
            break;
        case evmc_opcode::OP_CALL:
        case evmc_opcode::OP_CALLCODE:
            trace_memory = TraceMemory{stack[-5][0], stack[-6][0]};
            break;
        case evmc_opcode::OP_CREATE:
        case evmc_opcode::OP_CREATE2:
            trace_memory = TraceMemory{0, 0};
            break;
        default:
            break;
    }
}

void push_memory_offset_len(std::uint8_t op_code, const evmone::uint256* stack, std::stack<TraceMemory>& tms) {
    switch (op_code) {
        case evmc_opcode::OP_STATICCALL:
        case evmc_opcode::OP_DELEGATECALL:
            tms.emplace(TraceMemory{stack[-4][0], stack[-5][0]});
            break;
        case evmc_opcode::OP_CALL:
        case evmc_opcode::OP_CALLCODE:
            tms.emplace(TraceMemory{stack[-5][0], stack[-6][0]});
            break;
        case evmc_opcode::OP_CREATE:
        case evmc_opcode::OP_CREATE2:
            tms.emplace(TraceMemory{0, 0});
            break;
        default:
            break;
    }
}

std::string get_op_name(const char* const* names, std::uint8_t opcode) {
    const auto name = names[opcode];
    if (name != nullptr) {
        return name;
    }
    auto hex = evmc::hex(opcode);
    if (opcode < 16) {
        hex = hex.substr(1);
    }
    return "opcode 0x" + hex + " not defined";
}

static const char* PADDING = "0x0000000000000000000000000000000000000000000000000000000000000000";
std::string to_string(intx::uint256 value) {
    const auto out = intx::to_string(value, 16);
    std::string padding = std::string{PADDING};
    return padding.substr(0, padding.size() - out.size()) + out;
}

void VmTraceTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
    }
    if (precompile::is_precompile(msg.code_address, rev)) {
        is_precompile_ = true;
        return;
    }

    start_gas_.push(msg.gas);

    if (msg.depth == 0) {
        vm_trace_.code = "0x" + silkworm::to_hex(code);
        traces_stack_.emplace(vm_trace_);
        if (transaction_index_ == -1) {
            index_prefix_.emplace("");
        } else {
            index_prefix_.push(std::to_string(transaction_index_) + "-");
        }
    } else if (!vm_trace_.ops.empty()) {
        auto& vm_trace = traces_stack_.top().get();

        auto index_prefix = index_prefix_.top();
        index_prefix = index_prefix + std::to_string(vm_trace.ops.size() - 1) + "-";
        index_prefix_.push(index_prefix);

        auto& op = vm_trace.ops[vm_trace.ops.size() - 1];
        if (op.op_code == evmc_opcode::OP_STATICCALL || op.op_code == evmc_opcode::OP_DELEGATECALL || op.op_code == evmc_opcode::OP_CALL) {
            auto& op_1 = vm_trace.ops[vm_trace.ops.size() - 2];
            auto cap = op_1.trace_ex.used - msg.gas;
            op.depth = msg.depth;
            op.gas_cost = op.gas_cost - msg.gas;
            op.call_gas_cap = cap;
        }
        op.sub = std::make_shared<VmTrace>();
        traces_stack_.emplace(*op.sub);
        op.sub->code = "0x" + silkworm::to_hex(code);
    }

    auto& index_prefix = index_prefix_.top();
    SILK_DEBUG << "VmTraceTracer::on_execution_start:"
               << " depth: " << msg.depth
               << ", gas: " << std::dec << msg.gas
               << ", recipient: " << evmc::address{msg.recipient}
               << ", sender: " << evmc::address{msg.sender}
               << ", code: " << silkworm::to_hex(code)
               << ", code_address: " << evmc::address{msg.code_address}
               << ", input_size: " << msg.input_size
               << ", index_prefix: " << index_prefix;
}

void VmTraceTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int /*stack_height*/, const int64_t gas,
                                         const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    const auto op_code = execution_state.original_code[pc];
    auto op_name = get_op_name(opcode_names_, op_code);

    auto& vm_trace = traces_stack_.top().get();
    if (!vm_trace.ops.empty()) {
        auto& op = vm_trace.ops[vm_trace.ops.size() - 1];
        if (op.precompiled_call_gas) {
            op.gas_cost = op.gas_cost - op.precompiled_call_gas.value();
        } else if (op.depth == execution_state.msg->depth) {
            op.gas_cost = op.gas_cost - gas;
        }
        op.trace_ex.used = gas;

        copy_memory(execution_state.memory, op.trace_ex.memory);
        copy_stack(op.op_code, stack_top, op.trace_ex.stack);
    }

    auto index_prefix = index_prefix_.top() + std::to_string(vm_trace.ops.size());

    TraceOp trace_op;
    trace_op.gas_cost = gas;
    trace_op.idx = index_prefix;
    trace_op.depth = execution_state.msg->depth;
    trace_op.op_code = op_code;
    trace_op.op_name = op_name;
    trace_op.pc = pc;

    copy_memory_offset_len(op_code, stack_top, trace_op.trace_ex.memory);
    copy_store(op_code, stack_top, trace_op.trace_ex.storage);

    vm_trace.ops.push_back(trace_op);
    SILK_DEBUG << "VmTraceTracer::on_instruction_start:"
               << " pc: " << std::dec << pc
               << ", opcode: 0x" << std::hex << evmc::hex(op_code)
               << ", opcode_name: " << op_name
               << ", index_prefix: " << index_prefix
               << ", execution_state: {"
               << "   gas_left: " << std::dec << gas
               << ",   status: " << execution_state.status
               << ",   msg.gas: " << std::dec << execution_state.msg->gas
               << ",   msg.depth: " << std::dec << execution_state.msg->depth;
}

void VmTraceTracer::on_precompiled_run(const evmc_result& result, int64_t gas, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    SILK_DEBUG << "VmTraceTracer::on_precompiled_run:"
               << " status: " << result.status_code << ", gas: " << std::dec << gas << "\n";

    if (!vm_trace_.ops.empty()) {
        auto& op = vm_trace_.ops[vm_trace_.ops.size() - 1];
        op.precompiled_call_gas = gas;
        op.sub = std::make_shared<VmTrace>();
        op.sub->code = "0x";
    }
}

void VmTraceTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (is_precompile_) {
        is_precompile_ = false;
        return;
    }
    auto& vm_trace = traces_stack_.top().get();
    traces_stack_.pop();

    int64_t start_gas = start_gas_.top();
    start_gas_.pop();

    index_prefix_.pop();

    SILK_DEBUG << "VmTraceTracer::on_execution_end:"
               << " result.status_code: " << result.status_code
               << ", start_gas: " << std::dec << start_gas
               << ", gas_left: " << std::dec << result.gas_left;

    if (vm_trace.ops.empty()) {
        return;
    }
    auto& op = vm_trace.ops[vm_trace.ops.size() - 1];

    if (op.op_code == evmc_opcode::OP_STOP && vm_trace.ops.size() == 1) {
        vm_trace.ops.clear();
        return;
    }

    switch (result.status_code) {
        case evmc_status_code::EVMC_OUT_OF_GAS:
            op.trace_ex.used = result.gas_left;
            op.gas_cost -= result.gas_left;
            break;

        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
            op.trace_ex.used = op.gas_cost;
            op.gas_cost = 0;
            op.trace_ex.used -= op.gas_cost;
            break;

        case evmc_status_code::EVMC_REVERT:
        default:
            op.gas_cost = op.gas_cost - result.gas_left;
            op.trace_ex.used = result.gas_left;
            break;
    }
}

void TraceTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
    }

    if (precompile::is_precompile(msg.code_address, rev)) {
        is_precompile_ = true;
        return;
    }

    auto sender = evmc::address{msg.sender};
    auto recipient = evmc::address{msg.recipient};
    auto code_address = evmc::address{msg.code_address};

    current_depth_ = msg.depth;

    auto create = (!initial_ibs_.exists(recipient) && created_address_.find(recipient) == created_address_.end() && recipient != code_address);

    start_gas_.push(msg.gas);

    std::size_t index = traces_.size();
    traces_.resize(traces_.size() + 1);

    Trace& trace = traces_[index];
    trace.type = create ? "create" : "call";

    auto& trace_action = std::get<TraceAction>(trace.action);
    trace_action.from = sender;
    trace_action.gas = msg.gas;
    trace_action.value = intx::be::load<intx::uint256>(msg.value);

    trace.trace_result.emplace();
    if (create) {
        created_address_.insert(recipient);
        trace_action.init = code;
        trace.trace_result->code.emplace();
        trace.trace_result->address = recipient;
    } else {
        trace.trace_result->output.emplace();
        trace_action.input = silkworm::ByteView{msg.input_data, msg.input_size};
        trace_action.to = recipient;
        bool in_static_mode = (msg.flags & evmc_flags::EVMC_STATIC) != 0;
        switch (msg.kind) {
            case evmc_call_kind::EVMC_CALL:
                trace_action.call_type = in_static_mode ? "staticcall" : "call";
                break;
            case evmc_call_kind::EVMC_DELEGATECALL:
                trace_action.call_type = "delegatecall";
                trace_action.to = code_address;
                trace_action.from = recipient;
                break;
            case evmc_call_kind::EVMC_CALLCODE:
                trace_action.call_type = "callcode";
                break;
            case evmc_call_kind::EVMC_CREATE:
            case evmc_call_kind::EVMC_CREATE2:
                break;
        }
    }

    if (msg.depth > 0) {
        if (!index_stack_.empty()) {
            auto index_stack = index_stack_.top();
            Trace& calling_trace = traces_[index_stack];

            trace.trace_address = calling_trace.trace_address;
            trace.trace_address.push_back(calling_trace.sub_traces);
            calling_trace.sub_traces++;
        }
    } else {
        initial_gas_ = msg.gas;
    }
    index_stack_.push(index);

    SILK_DEBUG << "TraceTracer::on_execution_start: gas: " << std::dec << msg.gas
               << " create: " << create
               << ", msg.depth: " << msg.depth
               << ", msg.kind: " << msg.kind
               << ", sender: " << sender
               << ", recipient: " << recipient << " (created: " << create << ")"
               << ", code_address: " << code_address
               << ", msg.value: " << intx::hex(intx::be::load<intx::uint256>(msg.value))
               << ", code: " << silkworm::to_hex(code);
}

void TraceTracer::on_instruction_start(uint32_t pc, const intx::uint256* /*stack_top*/, const int /*stack_height*/, const int64_t gas,
                                       const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    const auto opcode = execution_state.original_code[pc];
    auto opcode_name = get_op_name(opcode_names_, opcode);

    SILK_DEBUG << "TraceTracer::on_instruction_start:"
               << " pc: " << std::dec << pc
               << ", opcode: 0x" << std::hex << evmc::hex(opcode)
               << ", opcode_name: " << opcode_name
               << ", recipient: " << evmc::address{execution_state.msg->recipient}
               << ", sender: " << evmc::address{execution_state.msg->sender}
               << ", execution_state: {"
               << "   gas_left: " << std::dec << gas
               << ",   status: " << execution_state.status
               << ",   msg.gas: " << std::dec << execution_state.msg->gas
               << ",   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";
}

void TraceTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (is_precompile_) {
        is_precompile_ = false;
        return;
    }
    auto index = index_stack_.top();
    auto start_gas = start_gas_.top();

    Trace& trace = traces_[index];
    if (!trace.trace_result->code) {
        start_gas_.pop();
        index_stack_.pop();
    }

    if (current_depth_ > 0) {
        if (trace.trace_result->code) {
            trace.trace_result->code = silkworm::ByteView{result.output_data, result.output_size};
        } else if (trace.trace_result->output) {
            trace.trace_result->output = silkworm::ByteView{result.output_data, result.output_size};
        }
    }

    current_depth_--;

    switch (result.status_code) {
        case evmc_status_code::EVMC_SUCCESS:
            trace.trace_result->gas_used = start_gas - result.gas_left;
            break;
        case evmc_status_code::EVMC_REVERT:
            trace.error = "Reverted";
            trace.trace_result->gas_used = start_gas - result.gas_left;
            break;
        case evmc_status_code::EVMC_OUT_OF_GAS:
        case evmc_status_code::EVMC_STACK_OVERFLOW:
            trace.error = "out of gas";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
        case evmc_status_code::EVMC_INVALID_INSTRUCTION:
            trace.error = "bad instruction";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_STACK_UNDERFLOW:
            trace.error = "stack underflow";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_BAD_JUMP_DESTINATION:
            trace.error = "bad jump destination";
            trace.trace_result.reset();
            break;
        default:
            trace.error = "";
            trace.trace_result.reset();
            break;
    }

    SILK_DEBUG << "TraceTracer::on_execution_end:"
               << " result.status_code: " << result.status_code
               << " start_gas: " << std::dec << start_gas
               << " gas_left: " << std::dec << result.gas_left;
}

void TraceTracer::on_creation_completed(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (index_stack_.empty())
        return;
    auto index = index_stack_.top();
    auto start_gas = start_gas_.top();
    index_stack_.pop();
    start_gas_.pop();
    Trace& trace = traces_[index];
    trace.trace_result->gas_used = start_gas - result.gas_left;
}

void TraceTracer::on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    SILK_DEBUG << "TraceTracer::on_reward_granted:"
               << " result.status_code: " << result.status
               << ", result.gas_left: " << result.gas_left
               << ", initial_gas: " << std::dec << initial_gas_
               << ", result.data: " << silkworm::to_hex(result.data);

    // Reward only on first trace
    if (traces_.empty()) {
        return;
    }
    Trace& trace = traces_[0];

    switch (result.status) {
        case evmc_status_code::EVMC_SUCCESS:
            trace.trace_result->gas_used = initial_gas_ - int64_t(result.gas_left);
            if (!result.data.empty()) {
                if (trace.trace_result->code) {
                    trace.trace_result->code = result.data;
                } else if (trace.trace_result->output) {
                    trace.trace_result->output = result.data;
                }
            }
            break;
        case evmc_status_code::EVMC_REVERT:
            trace.error = "Reverted";
            trace.trace_result->gas_used = initial_gas_ - int64_t(result.gas_left);
            if (!result.data.empty()) {
                if (trace.trace_result->code) {
                    trace.trace_result->code = result.data;
                } else if (trace.trace_result->output) {
                    trace.trace_result->output = result.data;
                }
            }
            break;
        case evmc_status_code::EVMC_OUT_OF_GAS:
        case evmc_status_code::EVMC_STACK_OVERFLOW:
            trace.error = "out of gas";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
        case evmc_status_code::EVMC_INVALID_INSTRUCTION:
            trace.error = "bad instruction";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_STACK_UNDERFLOW:
            trace.error = "stack underflow";
            trace.trace_result.reset();
            break;
        case evmc_status_code::EVMC_BAD_JUMP_DESTINATION:
            trace.error = "bad jump destination";
            trace.trace_result.reset();
            break;
        default:
            trace.error = "";
            trace.trace_result.reset();
            break;
    }
}

intx::uint256 StateAddresses::get_balance(const evmc::address& address) const noexcept {
    auto it = balances_.find(address);
    if (it != balances_.end()) {
        return it->second;
    }
    return initial_ibs_.get_balance(address);
}

uint64_t StateAddresses::get_nonce(const evmc::address& address) const noexcept {
    auto it = nonces_.find(address);
    if (it != nonces_.end()) {
        return it->second;
    }
    return initial_ibs_.get_nonce(address);
}

silkworm::ByteView StateAddresses::get_code(const evmc::address& address) const noexcept {
    auto it = codes_.find(address);
    if (it != codes_.end()) {
        return it->second;
    }
    return initial_ibs_.get_code(address);
}

void StateDiffTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
    }
    if (precompile::is_precompile(msg.code_address, rev)) {
        is_precompile_ = true;
        return;
    }

    auto recipient = evmc::address{msg.recipient};
    code_[recipient] = code;

    auto exists = state_addresses_.exists(recipient);

    SILK_DEBUG << "StateDiffTracer::on_execution_start: gas: " << std::dec << msg.gas
               << ", depth: " << msg.depth
               << ", sender: " << evmc::address{msg.sender}
               << ", recipient: " << recipient << " (exists: " << exists << ")"
               << ", code: " << silkworm::to_hex(code);
}

void StateDiffTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int /*stack_height*/, const int64_t gas,
                                           const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    const auto opcode = execution_state.original_code[pc];
    auto opcode_name = get_op_name(opcode_names_, opcode);

    if (opcode == evmc_opcode::OP_SSTORE) {
        auto key = to_string(stack_top[0]);
        auto value = to_string(stack_top[-1]);
        auto address = evmc::address{execution_state.msg->recipient};
        auto& keys = diff_storage_[address];
        keys.insert(key);
    }

    SILK_DEBUG << "StateDiffTracer::on_instruction_start:"
               << " pc: " << std::dec << pc
               << ", opcode_name: " << opcode_name
               << ", recipient: " << evmc::address{execution_state.msg->recipient}
               << ", sender: " << evmc::address{execution_state.msg->sender}
               << ", execution_state: {"
               << "   gas_left: " << std::dec << gas
               << ",   status: " << execution_state.status
               << ",   msg.gas: " << std::dec << execution_state.msg->gas
               << ",   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";
}

void StateDiffTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (is_precompile_) {
        is_precompile_ = false;
        return;
    }
    SILK_DEBUG << "StateDiffTracer::on_execution_end:"
               << " result.status_code: " << result.status_code
               << ", gas_left: " << std::dec << result.gas_left;
}

void StateDiffTracer::on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept {
    SILK_DEBUG << "StateDiffTracer::on_reward_granted:"
               << " result.status_code: " << result.status
               << ", result.gas_left: " << result.gas_left
               << ", #touched: " << std::dec << intra_block_state.touched().size();

    for (const auto& address : intra_block_state.touched()) {
        auto initial_exists = state_addresses_.exists(address);
        auto exists = intra_block_state.exists(address);
        auto& diff_storage = diff_storage_[address];

        auto address_key = address_to_hex(address);
        auto& entry = state_diff_[address_key];
        if (initial_exists) {
            auto initial_balance = state_addresses_.get_balance(address);
            auto initial_code = state_addresses_.get_code(address);
            auto initial_nonce = state_addresses_.get_nonce(address);
            if (exists) {
                bool all_equals = true;
                auto final_balance = intra_block_state.get_balance(address);
                if (initial_balance != final_balance) {
                    all_equals = false;
                    entry.balance = DiffValue{
                        "0x" + intx::to_string(initial_balance, 16),
                        "0x" + intx::to_string(final_balance, 16)};
                }
                auto final_code = intra_block_state.get_code(address);
                if (initial_code != final_code) {
                    all_equals = false;
                    entry.code = DiffValue{
                        "0x" + silkworm::to_hex(initial_code),
                        "0x" + silkworm::to_hex(final_code)};
                }
                auto final_nonce = intra_block_state.get_nonce(address);
                if (initial_nonce != final_nonce) {
                    all_equals = false;
                    entry.nonce = DiffValue{
                        to_quantity(initial_nonce),
                        to_quantity(final_nonce)};
                }
                for (auto& key : diff_storage) {
                    auto key_b32 = silkworm::bytes32_from_hex(key);

                    auto initial_storage = intra_block_state.get_original_storage(address, key_b32);
                    auto final_storage = intra_block_state.get_current_storage(address, key_b32);

                    if (initial_storage != final_storage) {
                        all_equals = false;
                        entry.storage[key] = DiffValue{
                            silkworm::to_hex(intra_block_state.get_original_storage(address, key_b32), true),
                            silkworm::to_hex(intra_block_state.get_current_storage(address, key_b32), true)};
                    }
                }
                if (all_equals) {
                    state_diff_.erase(address_key);
                }
            } else {
                entry.balance = DiffValue{
                    "0x" + intx::to_string(initial_balance, 16)};
                entry.code = DiffValue{
                    "0x" + silkworm::to_hex(initial_code)};
                entry.nonce = DiffValue{
                    to_quantity(initial_nonce)};
                for (auto& key : diff_storage) {
                    auto key_b32 = silkworm::bytes32_from_hex(key);
                    entry.storage[key] = DiffValue{
                        silkworm::to_hex(intra_block_state.get_original_storage(address, key_b32), true)};
                }
            }
        } else if (exists) {
            const auto balance = intra_block_state.get_balance(address);
            entry.balance = DiffValue{
                {},
                "0x" + intx::to_string(balance, 16)};
            const auto code = intra_block_state.get_code(address);
            entry.code = DiffValue{
                {},
                "0x" + silkworm::to_hex(code)};
            const auto nonce = intra_block_state.get_nonce(address);
            entry.nonce = DiffValue{
                {},
                to_quantity(nonce)};

            bool to_be_removed = (balance == 0) && code.empty() && (nonce == 0);
            for (auto& key : diff_storage) {
                auto key_b32 = silkworm::bytes32_from_hex(key);
                if (intra_block_state.get_current_storage(address, key_b32) != evmc::bytes32{}) {
                    entry.storage[key] = DiffValue{
                        {},
                        silkworm::to_hex(intra_block_state.get_current_storage(address, key_b32), true)};
                }
                to_be_removed = false;
            }

            if (to_be_removed) {
                state_diff_.erase(address_key);
            }
        }
    }
};

void IntraBlockStateTracer::on_reward_granted(const silkworm::CallResult& result, const silkworm::IntraBlockState& intra_block_state) noexcept {
    SILK_DEBUG
        << "IntraBlockStateTracer::on_reward_granted:"
        << " result.status_code: " << result.status
        << ", result.gas_left: " << result.gas_left
        << ", #touched: " << intra_block_state.touched().size();

    for (auto& address : intra_block_state.touched()) {
        auto balance = intra_block_state.get_balance(address);
        state_addresses_.set_balance(address, balance);

        auto nonce = intra_block_state.get_nonce(address);
        state_addresses_.set_nonce(address, nonce);

        auto code = intra_block_state.get_code(address);
        state_addresses_.set_code(address, code);
    }
}

Task<std::vector<Trace>> TraceCallExecutor::trace_block(const BlockWithHash& block_with_hash, Filter& filter, json::Stream* stream) {
    std::vector<Trace> traces;

    const TraceConfig trace_block_config{
        .vm_trace = false,
        .trace = true,
        .state_diff = false,
    };
    const auto trace_call_results = co_await trace_block_transactions(block_with_hash.block, trace_block_config);
    for (std::uint64_t pos = 0; pos < trace_call_results.size(); pos++) {
        rpc::Transaction transaction{block_with_hash.block.transactions[pos]};
        if (!transaction.from) {
            transaction.recover_sender();
        }
        const auto tnx_hash = transaction.hash();

        const auto& trace_call_result = trace_call_results.at(pos);
        const auto& call_traces = trace_call_result.traces.trace;

        for (const auto& call_trace : call_traces) {
            Trace trace{call_trace};
            nlohmann::json json = trace;
            bool skip = !(filter.from_addresses.empty() && filter.to_addresses.empty());
            if (std::holds_alternative<TraceAction>(trace.action)) {
                const auto& action = std::get<TraceAction>(trace.action);
                if (skip && !filter.from_addresses.empty()) {
                    if (filter.from_addresses.find(action.from) != filter.from_addresses.end()) {
                        skip = false;
                    }
                }
                if (skip && !filter.to_addresses.empty() && action.to) {
                    if (filter.to_addresses.find(action.to.value()) != filter.to_addresses.end()) {
                        skip = false;
                    }
                }
            }
            if (!skip) {
                if (filter.after > 0) {
                    filter.after--;
                } else {
                    trace.block_number = block_with_hash.block.header.number;
                    trace.block_hash = block_with_hash.hash;
                    trace.transaction_position = pos;
                    trace.transaction_hash = tnx_hash;

                    if (stream != nullptr) {
                        stream->write_json(trace);
                    } else {
                        traces.push_back(trace);
                    }
                    filter.count--;
                }
            }
            if (filter.count == 0) {
                break;
            }
        }
        if (filter.count == 0) {
            break;
        }
    }

    if (!filter.from_addresses.empty() || !filter.to_addresses.empty()) {
        co_return traces;
    }

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");
    const auto rule_set_factory = protocol::rule_set_factory(*chain_config_ptr);
    const auto block_rewards = rule_set_factory->compute_reward(block_with_hash.block);

    if (filter.count > 0 && filter.after == 0) {
        if (block_rewards.miner) {
            RewardAction action;
            action.author = block_with_hash.block.header.beneficiary;
            action.reward_type = "block";
            action.value = block_rewards.miner;

            Trace trace;
            trace.block_number = block_with_hash.block.header.number;
            trace.block_hash = block_with_hash.hash;
            trace.type = "reward";
            trace.action = action;

            if (stream != nullptr) {
                stream->write_json(trace);
            } else {
                traces.push_back(trace);
            }
        }

        for (auto& ommer_reward : block_rewards.ommers) {
            RewardAction action;
            action.author = block_with_hash.block.header.beneficiary; /* to be fix */
            action.reward_type = "block";
            action.value = ommer_reward;

            Trace trace;
            trace.block_number = block_with_hash.block.header.number;
            trace.block_hash = block_with_hash.hash;
            trace.type = "reward";
            trace.action = action;

            if (stream != nullptr) {
                stream->write_json(trace);
            } else {
                traces.push_back(trace);
            }
        }
        filter.count--;
    } else if (filter.after > 0) {
        if (block_rewards.miner || !block_rewards.ommers.empty())
            filter.after--;
    }

    co_return traces;
}

Task<std::vector<TraceCallResult>> TraceCallExecutor::trace_block_transactions(const silkworm::Block& block, const TraceConfig& config) {
    auto block_number = block.header.number;
    const auto& transactions = block.transactions;

    SILK_TRACE << "trace_block_transactions: block_number: " << std::dec << block_number << " #txns: " << transactions.size() << " config: " << config;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto call_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::vector<TraceCallResult>)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                IntraBlockState initial_ibs{*state};

                StateAddresses state_addresses(initial_ibs);
                std::shared_ptr<EvmTracer> ibs_tracer = std::make_shared<trace::IntraBlockStateTracer>(state_addresses);

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};

                std::vector<TraceCallResult> trace_call_result(transactions.size());
                for (std::uint64_t index = 0; index < transactions.size(); index++) {
                    silkworm::Transaction transaction{block.transactions[index]};
                    if (!transaction.from) {
                        transaction.recover_sender();
                    }

                    auto& result = trace_call_result.at(index);
                    TraceCallTraces& traces = result.traces;
                    traces.transaction_hash = transaction.hash();

                    Tracers tracers;
                    if (config.vm_trace) {
                        traces.vm_trace.emplace();
                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::VmTraceTracer>(traces.vm_trace.value(), index);
                        tracers.push_back(tracer);
                    }
                    if (config.trace) {
                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::TraceTracer>(traces.trace, initial_ibs);
                        tracers.push_back(tracer);
                    }
                    if (config.state_diff) {
                        traces.state_diff.emplace();

                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::StateDiffTracer>(traces.state_diff.value(), state_addresses);
                        tracers.push_back(tracer);
                    }

                    tracers.push_back(ibs_tracer);

                    auto execution_result = executor.call(block, transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);
                    if (execution_result.pre_check_error) {
                        result.pre_check_error = execution_result.pre_check_error.value();
                    } else {
                        traces.output = "0x" + silkworm::to_hex(execution_result.data);
                    }
                    executor.reset();
                }
                boost::asio::post(current_executor, [trace_call_result, self = std::move(self)]() mutable {
                    self.complete(trace_call_result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return call_result;
}

Task<TraceCallResult> TraceCallExecutor::trace_call(const silkworm::Block& block, const Call& call, const TraceConfig& config) {
    rpc::Transaction transaction{call.to_transaction()};
    auto result = co_await execute(block.header.number, block, transaction, -1, config);
    co_return result;
}

Task<TraceManyCallResult> TraceCallExecutor::trace_calls(const silkworm::Block& block, const std::vector<TraceCall>& calls) {
    const auto block_number = block.header.number;
    SILK_DEBUG << "trace_call_many: "
               << " block_number: " << block_number
               << " #trace_calls: " << calls.size();

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;
    const auto ret_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(TraceManyCallResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number);
                silkworm::IntraBlockState initial_ibs{*state};
                StateAddresses state_addresses(initial_ibs);

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number);
                EVMExecutor executor{*chain_config_ptr, workers_, state};

                std::shared_ptr<silkworm::EvmTracer> ibs_tracer = std::make_shared<trace::IntraBlockStateTracer>(state_addresses);

                TraceManyCallResult result;
                for (std::size_t index{0}; index < calls.size(); index++) {
                    const auto& config = calls[index].trace_config;

                    silkworm::Transaction transaction{calls[index].call.to_transaction()};

                    Tracers tracers;
                    TraceCallTraces traces;
                    if (config.vm_trace) {
                        traces.vm_trace.emplace();
                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::VmTraceTracer>(traces.vm_trace.value(), index);
                        tracers.push_back(tracer);
                    }
                    if (config.trace) {
                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::TraceTracer>(traces.trace, initial_ibs);
                        tracers.push_back(tracer);
                    }
                    if (config.state_diff) {
                        traces.state_diff.emplace();

                        std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::StateDiffTracer>(traces.state_diff.value(), state_addresses);
                        tracers.push_back(tracer);
                    }
                    tracers.push_back(ibs_tracer);

                    auto execution_result = executor.call(block, transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);

                    if (execution_result.pre_check_error) {
                        result.pre_check_error = "first run for txIndex " + std::to_string(index) + " error: " + execution_result.pre_check_error.value();
                        result.traces.clear();
                        break;
                    }
                    traces.output = "0x" + silkworm::to_hex(execution_result.data);
                    result.traces.push_back(traces);

                    executor.reset();
                }
                boost::asio::post(current_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return ret_result;
}

Task<TraceDeployResult> TraceCallExecutor::trace_deploy_transaction(const silkworm::Block& block, const evmc::address& contract_address) {
    auto block_number = block.header.number;
    const auto& transactions = block.transactions;

    SILK_TRACE << "trace_deploy_transaction: block_number: " << std::dec << block_number << " #txns: " << transactions.size();

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto deploy_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(TraceDeployResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                silkworm::IntraBlockState initial_ibs{*state};

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};

                TraceDeployResult result;

                auto create_tracer = std::make_shared<trace::CreateTracer>(contract_address, initial_ibs);

                Tracers tracers{create_tracer};

                for (std::uint64_t index = 0; index < transactions.size(); index++) {
                    silkworm::Transaction transaction{block.transactions[index]};
                    if (!transaction.from) {
                        transaction.recover_sender();
                    }

                    executor.call(block, transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);
                    executor.reset();

                    if (create_tracer->found()) {
                        result.transaction_hash = transaction.hash();
                        result.contract_creator = transaction.from;
                        break;
                    }
                }
                boost::asio::post(current_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return deploy_result;
}

Task<std::vector<Trace>> TraceCallExecutor::trace_transaction(const BlockWithHash& block_with_hash, const rpc::Transaction& transaction) {
    std::vector<Trace> traces;

    const auto result = co_await execute(block_with_hash.block.header.number - 1, block_with_hash.block, transaction,
                                         gsl::narrow<int32_t>(transaction.transaction_index), {false, true, false});
    const auto& trace_result = result.traces.trace;

    const auto tnx_hash = transaction.hash();

    for (const auto& call_trace : trace_result) {
        Trace trace{call_trace};

        trace.block_number = block_with_hash.block.header.number;
        trace.block_hash = block_with_hash.hash;
        trace.transaction_position = transaction.transaction_index;
        trace.transaction_hash = tnx_hash;

        traces.push_back(trace);
    }

    co_return traces;
}

Task<TraceEntriesResult> TraceCallExecutor::trace_transaction_entries(const TransactionWithBlock& transaction_with_block) {
    auto block_number = transaction_with_block.block_with_hash->block.header.number;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto ret_entry_tracer = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::shared_ptr<trace::EntryTracer>)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                silkworm::IntraBlockState initial_ibs{*state};

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};

                auto entry_tracer = std::make_shared<trace::EntryTracer>(initial_ibs);

                Tracers tracers{entry_tracer};

                executor.call(transaction_with_block.block_with_hash->block, transaction_with_block.transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);

                boost::asio::post(current_executor, [entry_tracer, self = std::move(self)]() mutable {
                    self.complete(entry_tracer);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return ret_entry_tracer->result();
}

Task<std::string> TraceCallExecutor::trace_transaction_error(const TransactionWithBlock& transaction_with_block) {
    auto block_number = transaction_with_block.block_with_hash->block.header.number;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto ret_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::string)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                silkworm::IntraBlockState initial_ibs{*state};

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};
                Tracers tracers{};

                auto execution_result = executor.call(transaction_with_block.block_with_hash->block, transaction_with_block.transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);

                std::string result = "0x";
                if (execution_result.error_code != evmc_status_code::EVMC_SUCCESS) {
                    result = "0x" + silkworm::to_hex(execution_result.data);
                }
                boost::asio::post(current_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return ret_result;
}

Task<TraceOperationsResult> TraceCallExecutor::trace_operations(const TransactionWithBlock& transaction_with_block) {
    auto block_number = transaction_with_block.block_with_hash->block.header.number;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto ret_entry_tracer = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::shared_ptr<trace::OperationTracer>)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                silkworm::IntraBlockState initial_ibs{*state};

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};

                auto entry_tracer = std::make_shared<trace::OperationTracer>(initial_ibs);

                Tracers tracers{entry_tracer};

                executor.call(transaction_with_block.block_with_hash->block, transaction_with_block.transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);

                boost::asio::post(current_executor, [entry_tracer, self = std::move(self)]() mutable {
                    self.complete(entry_tracer);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return ret_entry_tracer->result();
}

Task<bool> TraceCallExecutor::trace_touch_transaction(const silkworm::Block& block, const silkworm::Transaction& txn, const evmc::address& address) {
    auto block_number = block.header.number;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto ret_entry_tracer = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::shared_ptr<trace::TouchTracer>)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                silkworm::IntraBlockState initial_ibs{*state};

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};

                auto tracer = std::make_shared<trace::TouchTracer>(address, initial_ibs);
                Tracers tracers{tracer};

                executor.call(block, txn, tracers, /*refund=*/true, /*gas_bailout=*/true);

                boost::asio::post(current_executor, [tracer, self = std::move(self)]() mutable {
                    self.complete(tracer);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return ret_entry_tracer->found();
}

Task<void> TraceCallExecutor::trace_filter(const TraceFilter& trace_filter, const ChainStorage& storage, json::Stream* stream) {
    SILK_TRACE << "TraceCallExecutor::trace_filter: filter " << trace_filter;

    const auto from_block_with_hash = co_await core::read_block_by_number_or_hash(block_cache_, storage, database_reader_, trace_filter.from_block);
    if (!from_block_with_hash) {
        const Error error{-32000, "invalid parameters: fromBlock not found"};
        stream->write_json_field("error", error);
        co_return;
    }
    const auto to_block_with_hash = co_await core::read_block_by_number_or_hash(block_cache_, storage, database_reader_, trace_filter.to_block);
    if (!to_block_with_hash) {
        const Error error{-32000, "invalid parameters: toBlock not found"};
        stream->write_json_field("error", error);
        co_return;
    }

    if (from_block_with_hash->block.header.number > to_block_with_hash->block.header.number) {
        const Error error{-32000, "invalid parameters: fromBlock cannot be greater than toBlock"};
        stream->write_json_field("error", error);
        co_return;
    }

    stream->write_field("result");
    stream->open_array();

    Filter filter;
    filter.from_addresses.insert(trace_filter.from_addresses.begin(), trace_filter.from_addresses.end());
    filter.to_addresses.insert(trace_filter.to_addresses.begin(), trace_filter.to_addresses.end());
    filter.after = trace_filter.after;
    filter.count = trace_filter.count;

    auto block_number = from_block_with_hash->block.header.number;
    auto block_with_hash = from_block_with_hash;
    while (block_number++ <= to_block_with_hash->block.header.number) {
        const Block block{block_with_hash, {}, false};
        SILK_TRACE << "TraceCallExecutor::trace_filter: processing "
                   << " block_number: " << block_number - 1
                   << " block: " << block;

        co_await trace_block(*block_with_hash, filter, stream);

        if (filter.count == 0) {
            break;
        }

        if (block_number == to_block_with_hash->block.header.number) {
            block_with_hash = to_block_with_hash;
        } else {
            block_with_hash = co_await core::read_block_by_number(block_cache_, storage, block_number);
        }
    }

    stream->close_array();

    SILK_TRACE << "TraceCallExecutor::trace_filter: end";

    co_return;
}

Task<TraceCallResult> TraceCallExecutor::execute(
    BlockNum block_number,
    const silkworm::Block& block,
    const rpc::Transaction& transaction,
    std::int32_t index,
    const TraceConfig& config) {
    SILK_DEBUG << "execute: "
               << " block_number: " << std::dec << block_number
               << " transaction: {" << transaction << "}"
               << " index: " << std::dec << index
               << " config: " << config;

    const auto chain_config_ptr = co_await chain_storage_.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;

    const auto trace_call_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(TraceCallResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number);
                silkworm::IntraBlockState initial_ibs{*state};

                Tracers tracers;
                StateAddresses state_addresses(initial_ibs);
                std::shared_ptr<silkworm::EvmTracer> tracer = std::make_shared<trace::IntraBlockStateTracer>(state_addresses);
                tracers.push_back(tracer);

                auto curr_state = tx_.create_state(current_executor, database_reader_, chain_storage_, block_number);
                EVMExecutor executor{*chain_config_ptr, workers_, curr_state};
                for (std::size_t idx{0}; idx < transaction.transaction_index; idx++) {
                    silkworm::Transaction txn{block.transactions[idx]};

                    if (!txn.from) {
                        txn.recover_sender();
                    }
                    const auto execution_result = executor.call(block, txn, tracers, /*refund=*/true, /*gas_bailout=*/true);
                    if (execution_result.pre_check_error) {
                        SILK_ERROR << "execution failed for tx " << idx << " due to pre-check error: " << *execution_result.pre_check_error;
                    }
                    executor.reset();
                }

                tracers.clear();
                TraceCallResult result;
                TraceCallTraces& traces = result.traces;
                if (config.vm_trace) {
                    traces.vm_trace.emplace();
                    tracers.push_back(std::make_shared<trace::VmTraceTracer>(traces.vm_trace.value(), index));
                }
                if (config.trace) {
                    tracers.push_back(std::make_shared<trace::TraceTracer>(traces.trace, initial_ibs));
                }
                if (config.state_diff) {
                    traces.state_diff.emplace();

                    tracers.push_back(std::make_shared<trace::StateDiffTracer>(traces.state_diff.value(), state_addresses));
                }
                const auto execution_result = executor.call(block, transaction, tracers, /*refund=*/true, /*gas_bailout=*/true);

                if (execution_result.pre_check_error) {
                    result.pre_check_error = execution_result.pre_check_error.value();
                } else {
                    traces.output = "0x" + silkworm::to_hex(execution_result.data);
                }
                boost::asio::post(current_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    co_return trace_call_result;
}

void CreateTracer::on_execution_start(evmc_revision, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (found_) {
        return;
    }
    auto sender = evmc::address{msg.sender};
    auto recipient = evmc::address{msg.recipient};
    auto code_address = evmc::address{msg.code_address};

    bool create = (!initial_ibs_.exists(recipient) && recipient != code_address);

    if (create && recipient == contract_address_) {
        this->found_ = true;
    }

    SILK_DEBUG << "CreateTracer::on_execution_start: gas: " << std::dec << msg.gas
               << " create: " << create
               << ", msg.depth: " << msg.depth
               << ", msg.kind: " << msg.kind
               << ", sender: " << sender
               << ", recipient: " << recipient << " (created: " << create << ")"
               << ", code_address: " << code_address
               << ", msg.value: " << intx::hex(intx::be::load<intx::uint256>(msg.value))
               << ", code: " << silkworm::to_hex(code);
}

void EntryTracer::on_execution_start(evmc_revision, const evmc_message& msg, evmone::bytes_view code) noexcept {
    auto sender = evmc::address{msg.sender};
    auto recipient = evmc::address{msg.recipient};
    auto code_address = evmc::address{msg.code_address};
    bool create = (!initial_ibs_.exists(recipient) && recipient != code_address);
    auto input = silkworm::ByteView{msg.input_data, msg.input_size};

    auto str_value = "0x" + intx::hex(intx::be::load<intx::uint256>(msg.value));
    auto str_input = "0x" + silkworm::to_hex(input);
    if (str_input == "0x") {
        str_input = "0x" + silkworm::to_hex(code);
    }

    if (create) {
        if (msg.depth > 0) {
            if (msg.kind == evmc_call_kind::EVMC_CREATE) {
                result_.push_back(TraceEntry{"CREATE", msg.depth, sender, recipient, str_value, str_input});
            } else if (msg.kind == evmc_call_kind::EVMC_CREATE2) {
                result_.push_back(TraceEntry{"CREATE2", msg.depth, sender, recipient, str_value, str_input});
            }
        } else {
            result_.push_back(TraceEntry{"CALL", msg.depth, sender, recipient, str_value, str_input});
        }
    } else {
        bool in_static_mode = (msg.flags & evmc_flags::EVMC_STATIC) != 0;
        switch (msg.kind) {
            case evmc_call_kind::EVMC_CALL:
                in_static_mode ? result_.push_back(TraceEntry{"STATICCALL", msg.depth, sender, recipient, "", str_input}) : result_.push_back(TraceEntry{"CALL", msg.depth, sender, recipient, str_value, str_input});
                break;
            case evmc_call_kind::EVMC_DELEGATECALL:
                result_.push_back(TraceEntry{"DELEGATECALL", msg.depth, recipient, code_address, "", str_input});
                break;
            case evmc_call_kind::EVMC_CALLCODE:
                result_.push_back(TraceEntry{"CALLCODE", msg.depth, sender, recipient, str_value, str_input});
                break;
            case evmc_call_kind::EVMC_CREATE:
            case evmc_call_kind::EVMC_CREATE2:
                break;
        }
    }

    SILK_DEBUG << "EntryTracer::on_execution_start: gas: " << std::dec << msg.gas
               << " create: " << create
               << ", msg.depth: " << msg.depth
               << ", msg.kind: " << msg.kind
               << ", sender: " << sender
               << ", recipient: " << recipient << " (created: " << create << ")"
               << ", code_address: " << code_address
               << ", msg.value: " << intx::hex(intx::be::load<intx::uint256>(msg.value))
               << ", code: " << silkworm::to_hex(code)
               << ", msg.input_data: " << to_hex(ByteView{msg.input_data, msg.input_size});
}

void OperationTracer::on_execution_start(evmc_revision, const evmc_message& msg, evmone::bytes_view code) noexcept {
    auto sender = evmc::address{msg.sender};
    auto recipient = evmc::address{msg.recipient};
    auto code_address = evmc::address{msg.code_address};

    auto depth = msg.depth;
    auto kind = msg.kind;

    bool create = (!initial_ibs_.exists(recipient) && recipient != code_address);
    auto str_value = "0x" + intx::hex(intx::be::load<intx::uint256>(msg.value));

    if (create && msg.depth > 0) {
        if (msg.kind == evmc_call_kind::EVMC_CREATE) {
            result_.push_back(InternalOperation{OperationType::OP_CREATE, sender, recipient, str_value});
        } else if (msg.kind == evmc_call_kind::EVMC_CREATE2) {
            result_.push_back(InternalOperation{OperationType::OP_CREATE2, sender, recipient, str_value});
        } else if (msg.kind == evmc_call_kind::EVMC_CALL && intx::be::load<intx::uint256>(msg.value) > 0) {
            result_.push_back(InternalOperation{OperationType::OP_TRANSFER, sender, recipient, str_value});
        }
    }

    SILK_DEBUG << "OperationTracer::on_execution_start: gas: " << std::dec << msg.gas
               << " create: " << create
               << ", msg.depth: " << depth
               << ", msg.kind: " << kind
               << ", sender: " << sender
               << ", recipient: " << recipient << " (created: " << create << ")"
               << ", code_address: " << code_address
               << ", msg.value: " << intx::hex(intx::be::load<intx::uint256>(msg.value))
               << ", code: " << silkworm::to_hex(code)
               << ", msg.input_data: " << to_hex(ByteView{msg.input_data, msg.input_size});
}

void TouchTracer::on_execution_start(evmc_revision, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (found_) {
        return;
    }
    auto sender = evmc::address{msg.sender};
    auto recipient = evmc::address{msg.recipient};
    auto code_address = evmc::address{msg.code_address};

    bool create = (!initial_ibs_.exists(recipient) && recipient != code_address);

    if (!found_ && (sender == address_ || recipient == address_ || code_address == address_)) {
        this->found_ = true;
    }

    SILK_DEBUG << "TouchTracer::on_execution_start: gas: " << std::dec << msg.gas
               << " create: " << create
               << ", msg.depth: " << msg.depth
               << ", msg.kind: " << msg.kind
               << ", sender: " << sender
               << ", recipient: " << recipient << " (created: " << create << ")"
               << ", code_address: " << code_address
               << ", msg.value: " << intx::hex(intx::be::load<intx::uint256>(msg.value))
               << ", code: " << silkworm::to_hex(code);
}

}  // namespace silkworm::rpc::trace
