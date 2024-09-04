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

#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/json/types.hpp>

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

std::string uint256_to_hex(const evmone::uint256& x) {
    std::stringstream ss;
    ss << "0x";

    bool leading_zeros = true;
    const uint64_t* px = &x[0];
    for (int i = 3; i >= 0; i--) {
        if (px[i] == 0 && leading_zeros) {
            continue;
        }
        if (leading_zeros) {
            ss << std::hex << px[i];
            leading_zeros = false;
        } else {
            ss << std::setfill('0') << std::setw(16) << std::hex << px[i];
        }
    }

    if (leading_zeros) {
        ss << "0";
    }

    return ss.str();
}

static void output_stack(std::vector<std::string>& vect, const evmone::uint256* stack, int stack_size) {
    vect.reserve(static_cast<size_t>(stack_size));
    for (int i = stack_size - 1; i >= 0; --i) {
        vect.push_back(uint256_to_hex(stack[-i]));
    }
}

void output_memory(std::vector<std::string>& vect, const evmone::Memory& memory) {
    const auto data = memory.data();
    vect.push_back(silkworm::to_hex({data, memory.size()}));
}

void insert_error(DebugLog& log, evmc_status_code status_code) {
    switch (status_code) {
        case evmc_status_code::EVMC_FAILURE:
        case evmc_status_code::EVMC_OUT_OF_GAS:
        case evmc_status_code::EVMC_STACK_OVERFLOW:
        case evmc_status_code::EVMC_STACK_UNDERFLOW:
            log.error = true;
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
        default:
            log.error = false;
            break;
    }
}

void DebugTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    last_opcode_ = std::nullopt;
    if (opcode_names_ == nullptr) {
        opcode_names_ = evmc_get_instruction_names_table(rev);
        metrics_ = evmc_get_instruction_metrics_table(rev);
    }
    start_gas_.push(msg.gas);

    const evmc::address recipient(msg.recipient);
    const evmc::address sender(msg.sender);

    SILK_DEBUG << "on_execution_start:"
               << " rev: " << rev
               << " gas: " << std::dec << msg.gas
               << " depth: " << msg.depth
               << " recipient: " << recipient
               << " sender: " << sender
               << " code: " << silkworm::to_hex(code);
}

void DebugTracer::on_instruction_start(uint32_t pc, const intx::uint256* stack_top, const int stack_height, const int64_t gas,
                                       const evmone::ExecutionState& execution_state, const silkworm::IntraBlockState& intra_block_state) noexcept {
    assert(execution_state.msg);
    const evmc::address recipient(execution_state.msg->recipient);
    const evmc::address sender(execution_state.msg->sender);

    const auto opcode = execution_state.original_code[pc];
    const auto opcode_name = get_opcode_name(opcode_names_, opcode);
    last_opcode_ = opcode;

    SILK_DEBUG << "on_instruction_start:"
               << " pc: " << std::dec << pc
               << " opcode: 0x" << std::hex << evmc::hex(opcode)
               << " opcode_name: " << opcode_name
               << " recipient: " << recipient
               << " sender: " << sender
               << " execution_state: {"
               << "   gas_left: " << std::dec << gas
               << "   status: " << execution_state.status
               << "   msg.gas: " << std::dec << execution_state.msg->gas
               << "   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";

    bool output_storage = false;
    if (!config_.disableStorage) {
        if (opcode == OP_SLOAD && stack_height >= 1) {
            const auto address = silkworm::bytes32_from_hex(intx::hex(stack_top[0]));
            const auto value = intra_block_state.get_current_storage(recipient, address);
            storage_[recipient][silkworm::to_hex(address)] = silkworm::to_hex(value);
            output_storage = true;
        } else if (opcode == OP_SSTORE && stack_height >= 2) {
            const auto address = silkworm::bytes32_from_hex(intx::hex(stack_top[0]));
            const auto value = silkworm::bytes32_from_hex(intx::hex(stack_top[-1]));
            storage_[recipient][silkworm::to_hex(address)] = silkworm::to_hex(value);
            output_storage = true;
        }
    }

    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];
        if (fix_call_gas_info_) {  // previuos opcodw was a CALL*
            if (execution_state.msg->depth == fix_call_gas_info_->depth) {
                if (fix_call_gas_info_->gas_cost) {
                    log.gas_cost = fix_call_gas_info_->gas_cost + fix_call_gas_info_->code_cost;
                }
            } else {
                if (fix_call_gas_info_->opcode == OP_CALLCODE) {
                    log.gas_cost += fix_call_gas_info_->stipend + fix_call_gas_info_->gas_cost + fix_call_gas_info_->call_gas;
                } else {
                    log.gas_cost = gas + fix_call_gas_info_->stipend + fix_call_gas_info_->code_cost;
                }
            }

            fix_call_gas_info_.reset();
        } else {
            const auto depth = log.depth;
            if (depth == execution_state.msg->depth + 1 || depth == execution_state.msg->depth) {
                log.gas_cost = log.gas - gas;
            }
        }
    }

    if (logs_.size() > 1) {
        auto& log = logs_.front();
        write_log(log);
        logs_.erase(logs_.begin());
    }

    fill_call_gas_info(opcode, execution_state, stack_top, stack_height, intra_block_state);

    DebugLog log;
    log.pc = pc;
    log.op = opcode_name;
    log.gas = gas;
    log.gas_cost = metrics_[opcode].gas_cost;
    log.depth = execution_state.msg->depth + 1;

    if (!config_.disableStack) {
        output_stack(log.stack, stack_top, stack_height);
    }
    if (!config_.disableMemory) {
        output_memory(log.memory, execution_state.memory);
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
    SILK_DEBUG << "DebugTracer::on_precompiled_run:"
               << " status: " << result.status_code
               << ", gas: " << std::dec << gas;

    if (fix_call_gas_info_) {
        fix_call_gas_info_->gas_cost += gas + fix_call_gas_info_->code_cost;
        fix_call_gas_info_->code_cost = 0;
        fix_call_gas_info_->precompiled = true;
    }
}

void DebugTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    auto start_gas = start_gas_.top();
    start_gas_.pop();

    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];

        insert_error(log, result.status_code);

        switch (result.status_code) {
            case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
            case evmc_status_code::EVMC_INVALID_INSTRUCTION:
            case evmc_status_code::EVMC_STACK_OVERFLOW:
            case evmc_status_code::EVMC_STACK_UNDERFLOW:
                log.gas_cost = 0;
                break;

            case evmc_status_code::EVMC_OUT_OF_GAS:
                if (fix_call_gas_info_) {
                    if (fix_call_gas_info_->opcode == OP_CALLCODE) {
                        log.gas_cost = fix_call_gas_info_->code_cost;
                    } else {
                        log.gas_cost += fix_call_gas_info_->gas_cost;
                    }
                }
                break;

            default:
                if (fix_call_gas_info_) {
                    if (result.gas_left == 0 && !fix_call_gas_info_->precompiled) {
                        log.gas_cost = fix_call_gas_info_->stipend + fix_call_gas_info_->gas_cost;
                    } else if (!fix_call_gas_info_->precompiled) {
                        log.gas_cost = result.gas_left + fix_call_gas_info_->gas_cost + fix_call_gas_info_->code_cost - fix_call_gas_info_->stipend;
                        fix_call_gas_info_->gas_cost = 0;
                    } else if (fix_call_gas_info_->precompiled) {
                        log.gas_cost = fix_call_gas_info_->gas_cost;
                        fix_call_gas_info_->gas_cost = 0;
                    }
                }
                break;
        }

        /* EVM WA: EVMONE add OP_STOP at the end of tx if not present but doesn't notify to the tracer. Add sw to add STOP to the op list */
        if (result.status_code == EVMC_SUCCESS && last_opcode_ && last_opcode_ != OP_SELFDESTRUCT && last_opcode_ != OP_RETURN && last_opcode_ != OP_STOP) {
            DebugLog newlog;
            newlog.pc = log.pc + 1;
            newlog.op = get_opcode_name(opcode_names_, OP_STOP);
            newlog.gas = log.gas - log.gas_cost;
            newlog.gas_cost = 0;
            newlog.depth = log.depth;
            newlog.memory = log.memory;
            logs_.push_back(newlog);
        }
    }

    if (logs_.size() > 1) {
        auto& log = logs_.front();
        write_log(log);
        logs_.erase(logs_.begin());
    }

    SILK_DEBUG << "on_execution_end:"
               << " result.status_code: " << result.status_code
               << " start_gas: " << std::dec << start_gas
               << " gas_left: " << std::dec << result.gas_left;
}

void DebugTracer::flush_logs() {
    for (const auto& log : logs_) {
        write_log(log);
    }
}

int64_t memory_cost(const evmone::Memory& memory, std::uint64_t offset, std::uint64_t size) noexcept {
    if (size == 0) {
        return 0;
    }
    const auto new_size = offset + size;
    if (new_size <= memory.size()) {
        return 0;
    }

    const auto new_words = evmone::num_words(new_size);
    const auto current_words = static_cast<int64_t>(memory.size() / evmone::word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    return cost;
}

void DebugTracer::fill_call_gas_info(unsigned char opcode, const evmone::ExecutionState& execution_state, const intx::uint256* stack_top, const int stack_height, const silkworm::IntraBlockState& intra_block_state) {
    if (opcode != OP_CALL && opcode != OP_CALLCODE && opcode != OP_STATICCALL && opcode != OP_DELEGATECALL && opcode != OP_CREATE && opcode != OP_CREATE2) {
        return;
    }
    fix_call_gas_info_.emplace(FixCallGasInfo{opcode, execution_state.msg->depth, 0, metrics_[opcode].gas_cost});

    auto idx = 0;
    const auto call_gas = stack_top[idx--];  // gas
    const auto dst = intx::be::trunc<evmc::address>(stack_top[idx--]);
    const auto value = (opcode == OP_STATICCALL || opcode == OP_DELEGATECALL) ? 0 : stack_top[idx--];
    const auto input_offset = static_cast<std::uint64_t>(stack_top[idx--]);
    const auto input_size = static_cast<std::uint64_t>(stack_top[idx--]);
    const auto output_offset = static_cast<std::uint64_t>(stack_top[idx--]);
    const auto output_size = static_cast<std::uint64_t>(stack_top[idx--]);

    SILK_DEBUG << "DebugTracer::evaluate_call_fixes:"
               << " gas: " << std::dec << call_gas
               << ", input_offset: " << std::dec << input_offset
               << ", input_size: " << std::dec << input_size
               << ", output_offset: " << std::dec << output_offset
               << ", output_size: " << std::dec << output_size;

    if (call_gas < std::numeric_limits<int64_t>::max()) {
        fix_call_gas_info_->call_gas = static_cast<std::int64_t>(call_gas);
    }
    fix_call_gas_info_->gas_cost += memory_cost(execution_state.memory, input_offset, input_size);
    fix_call_gas_info_->gas_cost += memory_cost(execution_state.memory, output_offset, output_size);

    if (value != 0) {
        fix_call_gas_info_->gas_cost += 9000;
    }
    if (opcode == OP_CALL) {
        if (opcode == OP_CALL && stack_height >= 7 && value != 0) {
            fix_call_gas_info_->stipend = 2300;  // for CALLs with value, include stipend
        }
        if ((value != 0 || execution_state.rev < EVMC_SPURIOUS_DRAGON) && !intra_block_state.exists(dst)) {
            fix_call_gas_info_->gas_cost += 25000;  // add ACCOUNT_CREATION_COST as in instructions_calls.cpp:105
        }
        SILK_DEBUG << "DebugTracer::evaluate_call_fixes:"
                   << " call_gas: " << call_gas
                   << " dst: " << dst
                   << " value: " << value
                   << " gas_cost: " << fix_call_gas_info_->gas_cost
                   << " stipend: " << fix_call_gas_info_->stipend;
    }
}

void AccountTracer::on_execution_end(const evmc_result& /*result*/, const silkworm::IntraBlockState& intra_block_state) noexcept {
    nonce = intra_block_state.get_nonce(address_);
    balance = intra_block_state.get_balance(address_);
    code_hash = intra_block_state.get_code_hash(address_);
    code = intra_block_state.get_code(address_);
}

void DebugTracer::write_log(const DebugLog& log) {
    stream_.open_object();
    stream_.write_field("depth", log.depth);
    stream_.write_field("gas", log.gas);
    stream_.write_field("gasCost", log.gas_cost);
    stream_.write_field("op", log.op);
    stream_.write_field("pc", log.pc);

    if (!config_.disableStack) {
        stream_.write_field("stack");
        stream_.open_array();
        for (const auto& item : log.stack) {
            stream_.write_entry(item);
        }
        stream_.close_array();
    }
    if (!config_.disableMemory) {
        stream_.write_field("memory");
        stream_.open_array();
        for (const auto& item : log.memory) {
            const std::size_t len = 64;
            const auto data = item.data();
            for (std::size_t start = 0; start < item.size(); start += len) {
                stream_.write_entry({data + start, len});
            }
        }
        stream_.close_array();
    }
    if (!config_.disableStorage && !log.storage.empty()) {
        stream_.write_field("storage");
        stream_.open_object();
        for (const auto& entry : log.storage) {
            stream_.write_field(entry.first, entry.second);
        }
        stream_.close_object();
    }
    if (log.error) {
        stream_.write_field("error");
        stream_.open_object();
        stream_.close_object();
    }

    stream_.close_object();
}

Task<void> DebugExecutor::trace_block(json::Stream& stream, const ChainStorage& storage, BlockNum block_number) {
    const auto block_with_hash = co_await rpc::core::read_block_by_number(block_cache_, storage, block_number);
    if (!block_with_hash) {
        co_return;
    }
    stream.write_field("result");
    stream.open_array();
    co_await execute(stream, storage, block_with_hash->block);
    stream.close_array();

    co_return;
}

Task<void> DebugExecutor::trace_block(json::Stream& stream, const ChainStorage& storage, const evmc::bytes32& block_hash) {
    const auto block_with_hash = co_await rpc::core::read_block_by_hash(block_cache_, storage, block_hash);
    if (!block_with_hash) {
        co_return;
    }

    stream.write_field("result");
    stream.open_array();
    co_await execute(stream, storage, block_with_hash->block);
    stream.close_array();

    co_return;
}

Task<void> DebugExecutor::trace_call(json::Stream& stream, const BlockNumberOrHash& bnoh, const ChainStorage& storage, const Call& call) {
    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, storage, tx_, bnoh);
    if (!block_with_hash) {
        co_return;
    }
    rpc::Transaction transaction{call.to_transaction()};

    const auto& block = block_with_hash->block;
    const auto number = block.header.number;

    stream.write_field("result");
    stream.open_object();
    co_await execute(stream, storage, number, block, transaction, -1);
    stream.close_object();

    co_return;
}

Task<void> DebugExecutor::trace_transaction(json::Stream& stream, const ChainStorage& storage, const evmc::bytes32& tx_hash) {
    const auto tx_with_block = co_await rpc::core::read_transaction_by_hash(block_cache_, storage, tx_hash);

    if (!tx_with_block) {
        std::ostringstream oss;
        oss << "transaction " << silkworm::to_hex(tx_hash, true) << " not found";
        const Error error{-32000, oss.str()};
        stream.write_json_field("error", error);
    } else {
        const auto& block = tx_with_block->block_with_hash->block;
        const auto& transaction = tx_with_block->transaction;
        const auto number = block.header.number - 1;

        stream.write_field("result");
        stream.open_object();
        co_await execute(stream, storage, number, block, transaction, gsl::narrow<int32_t>(transaction.transaction_index));
        stream.close_object();
    }

    co_return;
}

Task<void> DebugExecutor::trace_call_many(json::Stream& stream, const ChainStorage& storage, const Bundles& bundles, const SimulationContext& context) {
    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, storage, tx_, context.block_number);
    if (!block_with_hash) {
        co_return;
    }
    auto transaction_index = context.transaction_index;
    if (transaction_index == -1) {
        transaction_index = static_cast<std::int32_t>(block_with_hash->block.transactions.size());
    }

    stream.write_field("result");
    stream.open_array();
    co_await execute(stream, storage, block_with_hash, bundles, transaction_index);
    stream.close_array();

    co_return;
}

Task<void> DebugExecutor::execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block) {
    auto block_number = block.header.number;
    const auto& transactions = block.transactions;

    SILK_DEBUG << "execute: block_number: " << block_number << " #txns: " << transactions.size() << " config: " << config_;

    const auto chain_config = co_await storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;
    co_await async_task(workers_.executor(), [&]() -> void {
        auto state = tx_.create_state(current_executor, storage, block_number - 1);
        EVMExecutor executor{chain_config, workers_, state};

        for (std::uint64_t idx = 0; idx < transactions.size(); idx++) {
            rpc::Transaction txn{block.transactions[idx]};
            SILK_DEBUG << "processing transaction: idx: " << idx << " txn: " << txn;

            auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

            stream.open_object();
            stream.write_field("result");
            stream.open_object();
            stream.write_field("structLogs");
            stream.open_array();

            Tracers tracers{debug_tracer};
            const auto execution_result = executor.call(block, txn, tracers, /* refund */ false, /* gasBailout */ false);

            debug_tracer->flush_logs();
            stream.close_array();

            stream.write_json_field("failed", !execution_result.success());
            if (!execution_result.pre_check_error) {
                stream.write_field("gas", txn.gas_limit - execution_result.gas_left);
                stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
            }

            stream.close_object();
            stream.write_field("txHash", txn.hash());
            stream.close_object();
        }
    });

    co_return;
}

Task<void> DebugExecutor::execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block, const Call& call) {
    rpc::Transaction transaction{call.to_transaction()};
    co_await execute(stream, storage, block.header.number, block, transaction, -1);
    co_return;
}

Task<void> DebugExecutor::execute(
    json::Stream& stream,
    const ChainStorage& storage,
    BlockNum block_number,
    const silkworm::Block& block,
    const Transaction& transaction,
    int32_t index) {
    SILK_TRACE << "DebugExecutor::execute: "
               << " block_number: " << block_number
               << " transaction: {" << transaction << "}"
               << " index: " << std::dec << index
               << " config: " << config_;

    const auto chain_config = co_await storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;
    co_await async_task(workers_.executor(), [&]() {
        auto state = tx_.create_state(current_executor, storage, block_number);
        EVMExecutor executor{chain_config, workers_, state};

        for (auto idx{0}; idx < index; idx++) {
            silkworm::Transaction txn{block.transactions[static_cast<size_t>(idx)]};
            executor.call(block, txn);
        }
        executor.reset();

        auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

        stream.write_field("structLogs");
        stream.open_array();

        Tracers tracers{debug_tracer};
        const auto execution_result = executor.call(block, transaction, tracers);

        debug_tracer->flush_logs();
        stream.close_array();

        SILK_DEBUG << "debug return: " << execution_result.error_message();

        stream.write_json_field("failed", !execution_result.success());
        if (!execution_result.pre_check_error) {
            stream.write_field("gas", transaction.gas_limit - execution_result.gas_left);
            stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
        }
    });

    co_return;
}

Task<void> DebugExecutor::execute(
    json::Stream& stream,
    const ChainStorage& storage,
    std::shared_ptr<BlockWithHash> block_with_hash,
    const Bundles& bundles,
    int32_t transaction_index) {
    const auto& block = block_with_hash->block;
    const auto& block_transactions = block.transactions;

    SILK_TRACE << "DebugExecutor::execute: "
               << " block number: " << block.header.number
               << " txns in block: " << block_transactions.size()
               << " bundles: [" << bundles << "]"
               << " transaction_index: " << std::dec << transaction_index
               << " config: " << config_;

    const auto chain_config = co_await storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;
    co_await async_task(workers_.executor(), [&]() {
        auto state = tx_.create_state(current_executor, storage, block.header.number);
        EVMExecutor executor{chain_config, workers_, state};

        for (auto idx{0}; idx < transaction_index; idx++) {
            silkworm::Transaction txn{block_transactions[static_cast<size_t>(idx)]};
            executor.call(block, txn);
        }
        executor.reset();

        for (const auto& bundle : bundles) {
            const auto& block_override = bundle.block_override;

            rpc::Block blockContext{{block_with_hash}};
            if (block_override.block_number) {
                blockContext.block_with_hash->block.header.number = block_override.block_number.value();
            }
            if (block_override.coin_base) {
                blockContext.block_with_hash->block.header.beneficiary = block_override.coin_base.value();
            }
            if (block_override.timestamp) {
                blockContext.block_with_hash->block.header.timestamp = block_override.timestamp.value();
            }
            if (block_override.difficulty) {
                blockContext.block_with_hash->block.header.difficulty = block_override.difficulty.value();
            }
            if (block_override.gas_limit) {
                blockContext.block_with_hash->block.header.gas_limit = block_override.gas_limit.value();
            }
            if (block_override.base_fee) {
                blockContext.block_with_hash->block.header.base_fee_per_gas = block_override.base_fee;
            }

            stream.open_array();

            for (const auto& call : bundle.transactions) {
                silkworm::Transaction txn{call.to_transaction()};

                stream.open_object();
                stream.write_field("structLogs");
                stream.open_array();

                auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);
                Tracers tracers{debug_tracer};

                const auto execution_result = executor.call(blockContext.block_with_hash->block, txn, tracers, /* refund */ false, /* gasBailout */ false);

                debug_tracer->flush_logs();
                stream.close_array();

                SILK_DEBUG << "debug return: " << execution_result.error_message();

                stream.write_json_field("failed", !execution_result.success());
                if (!execution_result.pre_check_error) {
                    stream.write_field("gas", txn.gas_limit - execution_result.gas_left);
                    stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
                }
                stream.close_object();
            }

            stream.close_array();
        }
    });

    co_return;
}

}  // namespace silkworm::rpc::debug
