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

#include "evm_debug.hpp"

#include <memory>
#include <string>

#include <evmc/hex.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::debug {

void from_json(const nlohmann::json& json, DebugConfig& tc) {
    json.at("disableStorage").get_to(tc.disableStorage);
    json.at("disableMemory").get_to(tc.disableMemory);
    json.at("disableStack").get_to(tc.disableStack);
}

std::ostream& operator<<(std::ostream& out, const DebugConfig& tc) {
    out << "disableStorage: " << std::boolalpha << tc.disableStorage;
    out << " disableMemory: " << std::boolalpha << tc.disableMemory;
    out << " disableStack: " << std::boolalpha << tc.disableStack;

    return out;
}

std::string get_opcode_name(const char* const* names, std::uint8_t opcode) {
    const auto name = names[opcode];
    return (name != nullptr) ? name : "opcode 0x" + evmc::hex(opcode) + " not defined";
}

static std::string EMPTY_MEMORY(64, '0');

void output_stack(std::vector<std::string>& vect, const evmone::uint256* stack, uint32_t stack_size) {
    vect.reserve(stack_size);
    for (int i = int(stack_size - 1); i >= 0; --i) {
        vect.push_back("0x" + intx::to_string(stack[-i], 16));
    }
}

void output_memory(std::vector<std::string>& vect, const evmone::Memory& memory) {
    std::size_t len = 32;
    vect.reserve(memory.size() / len);

    const auto data = memory.data();
    for (std::size_t start = 0; start < memory.size(); start += len) {
        std::string entry{evmc::hex({data + start, len})};
        vect.push_back(entry);
    }
}

void insert_error(DebugLog& log, evmc_status_code status_code) {
    switch (status_code) {
        case evmc_status_code::EVMC_FAILURE:
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
        case evmc_status_code::EVMC_OUT_OF_GAS:
            log.error = true;
            break;
        default:
            log.error = false;
            break;
    }
}

void DebugTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
    }
    start_gas_ = msg.gas;
    evmc::address recipient(msg.recipient);
    evmc::address sender(msg.sender);
    SILKRPC_DEBUG << "on_execution_start: gas: " << std::dec << msg.gas
                  << " depth: " << msg.depth
                  << " recipient: " << recipient
                  << " sender: " << sender
                  << " code: " << silkworm::to_hex(code)
                  << "\n";
}

void DebugTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int stack_height,
                                       const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept {
    assert(execution_state.msg);
    evmc::address recipient(execution_state.msg->recipient);
    evmc::address sender(execution_state.msg->sender);

    const auto opcode = execution_state.original_code[pc];
    auto opcode_name = get_opcode_name(opcode_names_, opcode);

    SILKRPC_DEBUG << "on_instruction_start:"
                  << " pc: " << std::dec << pc
                  << " opcode: 0x" << std::hex << evmc::hex(opcode)
                  << " opcode_name: " << opcode_name
                  << " recipient: " << recipient
                  << " sender: " << sender
                  << " execution_state: {"
                  << "   gas_left: " << std::dec << execution_state.gas_left
                  << "   status: " << execution_state.status
                  << "   msg.gas: " << std::dec << execution_state.msg->gas
                  << "   msg.depth: " << std::dec << execution_state.msg->depth
                  << "}\n";

    bool output_storage = false;
    if (!config_.disableStorage) {
        if (opcode_name == "SLOAD" && stack_height >= 1) {
            const auto address = silkworm::bytes32_from_hex(intx::hex(stack_top[0]));
            const auto value = intra_block_state.get_current_storage(recipient, address);
            storage_[recipient][silkworm::to_hex(address)] = silkworm::to_hex(value);
            output_storage = true;
        } else if (opcode_name == "SSTORE" && stack_height >= 2) {
            const auto address = silkworm::bytes32_from_hex(intx::hex(stack_top[0]));
            const auto value = silkworm::bytes32_from_hex(intx::hex(stack_top[-1]));
            storage_[recipient][silkworm::to_hex(address)] = silkworm::to_hex(value);
            output_storage = true;
        }
    }

    std::vector<std::string> current_memory;
    if (!config_.disableMemory) {
        output_memory(current_memory, execution_state.memory);
    }

    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];
        const auto depth = log.depth;
        if (depth == execution_state.msg->depth + 1) {
            if (gas_on_precompiled_) {
                log.gas_cost = log.gas - gas_on_precompiled_;
                gas_on_precompiled_ = 0;
            } else {
                log.gas_cost = log.gas - execution_state.gas_left;
            }
            if (!config_.disableMemory) {
                auto& memory = log.memory;
                for (std::size_t idx = memory.size(); idx < current_memory.size(); idx++) {
                    memory.push_back(EMPTY_MEMORY);
                }
            }
        } else if (depth == execution_state.msg->depth) {
            log.gas_cost = log.gas - execution_state.gas_left;
        }
    }
    if (logs_.size() > 1) {
        auto& log = logs_.front();
        write_log(log);
        logs_.erase(logs_.begin());
    }

    DebugLog log;
    log.pc = pc;
    log.op = opcode_name;
    log.gas = execution_state.gas_left;
    log.depth = execution_state.msg->depth + 1;

    if (!config_.disableStack) {
        output_stack(log.stack, stack_top, uint32_t(stack_height));
    }
    if (!config_.disableMemory) {
        log.memory = current_memory;
    }
    if (output_storage) {
        for (const auto& entry : storage_[recipient]) {
            log.storage[entry.first] = entry.second;
        }
    }
    insert_error(log, execution_state.status);

    logs_.push_back(log);
}

void DebugTracer::on_precompiled_run(const evmc_result& result, int64_t gas, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    SILKRPC_DEBUG << "DebugTracer::on_precompiled_run:"
                  << " status: " << result.status_code
                  << ", gas: " << std::dec << gas
                  << "\n";

    gas_on_precompiled_ = gas;
}

void DebugTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];

        insert_error(log, result.status_code);

        switch (result.status_code) {
            case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
                log.gas_cost = start_gas_ - log.gas;
                break;

            case evmc_status_code::EVMC_REVERT:
            case evmc_status_code::EVMC_OUT_OF_GAS:
            default:
                log.gas_cost = log.gas - result.gas_left;
                break;
        }
    }

    if (logs_.size() > 1) {
        auto& log = logs_.front();
        write_log(log);
        logs_.erase(logs_.begin());
    }

    SILKRPC_DEBUG << "on_execution_end:"
                  << " result.status_code: " << result.status_code
                  << " start_gas: " << std::dec << start_gas_
                  << " gas_left: " << std::dec << result.gas_left
                  << "\n";
}

void DebugTracer::flush_logs() {
    for (const auto& log : logs_) {
        write_log(log);
    }
}

void DebugTracer::write_log(const DebugLog& log) {
    nlohmann::json json;

    json["depth"] = log.depth;
    json["gas"] = log.gas;
    json["gasCost"] = log.gas_cost;
    json["op"] = log.op;
    json["pc"] = log.pc;
    if (!config_.disableStack) {
        json["stack"] = log.stack;
    }
    if (!config_.disableMemory) {
        json["memory"] = log.memory;
    }
    if (!config_.disableStorage && !log.storage.empty()) {
        json["storage"] = log.storage;
    }
    if (log.error) {
        json["error"] = nlohmann::json::object();
    }

    stream_.write_json(json);
}

template <typename WorldState, typename VM>
boost::asio::awaitable<void> DebugExecutor<WorldState, VM>::execute(json::Stream& stream, const silkworm::Block& block) {
    auto block_number = block.header.number;
    const auto& transactions = block.transactions;

    SILKRPC_DEBUG << "execute: block_number: " << block_number << " #txns: " << transactions.size() << " config: " << config_ << "\n";

    const auto chain_id = co_await core::rawdb::read_chain_id(database_reader_);
    const auto chain_config_ptr = lookup_chain_config(chain_id);
    state::RemoteState remote_state{io_context_, database_reader_, block_number - 1};
    EVMExecutor<WorldState, VM> executor{io_context_, *chain_config_ptr, workers_, remote_state};

    for (std::uint64_t idx = 0; idx < transactions.size(); idx++) {
        rpc::Transaction txn{block.transactions[idx]};
        if (!txn.from) {
            txn.recover_sender();
        }
        SILKRPC_DEBUG << "processing transaction: idx: " << idx << " txn: " << txn << "\n";

        auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

        stream.open_object();
        stream.write_field("result");
        stream.open_object();
        stream.write_field("structLogs");
        stream.open_array();

        Tracers tracers{debug_tracer};
        const auto execution_result = co_await executor.call(block, txn, tracers, /* refund */ false, /* gasBailout */ false);

        debug_tracer->flush_logs();
        stream.close_array();

        if (execution_result.pre_check_error) {
            SILKRPC_DEBUG << "debug failed: " << execution_result.pre_check_error.value() << "\n";

            stream.write_field("failed", true);
        } else {
            stream.write_field("failed", execution_result.error_code != evmc_status_code::EVMC_SUCCESS);
            stream.write_field("gas", txn.gas_limit - execution_result.gas_left);
            stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
        }
        stream.close_object();
        stream.close_object();
    }
    co_return;
}

template <typename WorldState, typename VM>
boost::asio::awaitable<void> DebugExecutor<WorldState, VM>::execute(json::Stream& stream, const silkworm::Block& block, const Call& call) {
    rpc::Transaction transaction{call.to_transaction()};
    co_await execute(stream, block.header.number, block, transaction, -1);
    co_return;
}

template <typename WorldState, typename VM>
boost::asio::awaitable<void> DebugExecutor<WorldState, VM>::execute(json::Stream& stream, uint64_t block_number,
                                                                    const silkworm::Block& block, const Transaction& transaction, int32_t index) {
    SILKRPC_INFO << "DebugExecutor::execute: "
                 << " block_number: " << block_number
                 << " transaction: {" << transaction << "}"
                 << " index: " << std::dec << index
                 << " config: " << config_
                 << "\n";

    const auto chain_id = co_await core::rawdb::read_chain_id(database_reader_);
    const auto chain_config_ptr = lookup_chain_config(chain_id);
    state::RemoteState remote_state{io_context_, database_reader_, block_number};
    EVMExecutor<WorldState, VM> executor{io_context_, *chain_config_ptr, workers_, remote_state};

    for (auto idx{0}; idx < index; idx++) {
        silkworm::Transaction txn{block.transactions[std::size_t(idx)]};

        if (!txn.from) {
            txn.recover_sender();
        }
        co_await executor.call(block, txn);
    }
    executor.reset();

    auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

    stream.write_field("structLogs");
    stream.open_array();

    Tracers tracers{debug_tracer};
    const auto execution_result = co_await executor.call(block, transaction, tracers);

    debug_tracer->flush_logs();
    stream.close_array();
    if (execution_result.pre_check_error) {
        SILKRPC_DEBUG << "debug failed: " << execution_result.pre_check_error.value() << "\n";

        stream.write_field("failed", true);
    } else {
        stream.write_field("failed", execution_result.error_code != evmc_status_code::EVMC_SUCCESS);
        stream.write_field("gas", transaction.gas_limit - execution_result.gas_left);
        stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
    }

    co_return;
}

template class DebugExecutor<>;

}  // namespace silkworm::rpc::debug
