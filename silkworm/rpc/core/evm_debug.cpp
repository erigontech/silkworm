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

#include <string>

#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions_traits.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/cached_chain.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc::debug {

void from_json(const nlohmann::json& json, DebugConfig& tc) {
    json.at("disableStorage").get_to(tc.disable_storage);
    json.at("disableMemory").get_to(tc.disable_memory);
    json.at("disableStack").get_to(tc.disable_stack);

    if (json.count("NoRefunds") != 0) {
        json.at("NoRefunds").get_to(tc.no_refunds);
    }
    if (json.count("TxIndex") != 0) {
        const auto& json_idx = json.at("TxIndex");
        if (json_idx.is_string()) {
            tc.tx_index = std::stol(json_idx.get<std::string>(), nullptr, 16);
        } else {
            tc.tx_index = json_idx.get<uint32_t>();
        }
    }
}

std::ostream& operator<<(std::ostream& out, const DebugConfig& tc) {
    out << "disableStorage: " << std::boolalpha << tc.disable_storage;
    out << " disableMemory: " << std::boolalpha << tc.disable_memory;
    out << " disableStack: " << std::boolalpha << tc.disable_stack;
    out << " NoRefunds: " << std::boolalpha << tc.no_refunds;
    if (tc.tx_index) {
        out << " TxIndex: " << std::dec << tc.tx_index.value();
    }

    return out;
}

std::string uint256_to_hex(const evmone::uint256& x) {
    std::stringstream ss;
    ss << "0x";

    bool leading_zeros = true;
    const uint64_t* px = &x[0];
    for (int i = 3; i >= 0; --i) {
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
        case evmc_status_code::EVMC_OUT_OF_GAS:
            log.error = "out of gas";
            break;
        case evmc_status_code::EVMC_STACK_OVERFLOW:
            log.error = {"stack overflow (" + std::to_string(log.stack_height) + " <=> " + std::to_string(evmone::instr::traits[log.op_code].stack_height_required) + ")"};
            break;
        case evmc_status_code::EVMC_STACK_UNDERFLOW:
            log.error = {"stack underflow (" + std::to_string(log.stack_height) + " <=> " + std::to_string(evmone::instr::traits[log.op_code].stack_height_required) + ")"};
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
        case evmc_status_code::EVMC_FAILURE:
        default:
            log.error = "";
            break;
    }
}

void DebugTracer::on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept {
    last_opcode_ = std::nullopt;
    if (opcode_names_ == nullptr) {
        latest_opcode_names_ = evmc_get_instruction_names_table(EVMC_LATEST_STABLE_REVISION);
        opcode_names_ = evmc_get_instruction_names_table(rev);
        metrics_ = evmc_get_instruction_metrics_table(rev);
    }

    const evmc::address recipient(msg.recipient);
    const evmc::address sender(msg.sender);

    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];  // it should be a CALL* opcode
        log.gas_cost = msg.gas_cost;
    }

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
    SILKWORM_ASSERT(execution_state.msg);
    const evmc::address recipient(execution_state.msg->recipient);
    const evmc::address sender(execution_state.msg->sender);

    const auto opcode = execution_state.original_code[pc];
    auto opcode_name = get_opcode_name(opcode_names_, opcode);
    if (!opcode_name) {
        opcode_name = get_opcode_name(latest_opcode_names_, opcode);
    }
    last_opcode_ = opcode;

    SILK_DEBUG << "on_instruction_start:"
               << " pc: " << std::dec << pc
               << " opcode: 0x" << std::hex << evmc::hex(opcode)
               << " opcode_name: " << opcode_name.value_or("UNDEFINED")
               << " recipient: " << recipient
               << " sender: " << sender
               << " execution_state: {"
               << "   gas_left: " << std::dec << gas
               << "   status: " << execution_state.status
               << "   msg.gas: " << std::dec << execution_state.msg->gas
               << "   msg.depth: " << std::dec << execution_state.msg->depth
               << "}";

    bool output_storage = false;
    if (!config_.disable_storage) {
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

        if (log.op_code == OP_RETURN || log.op_code == OP_STOP || log.op_code == OP_REVERT) {
            log.gas_cost = 0;
        } else if (log.depth == execution_state.msg->depth + 1) {
            log.gas_cost = execution_state.last_opcode_gas_cost;
        }
    }

    if (logs_.size() > 1) {
        auto& log = logs_.front();
        write_log(log);
        logs_.erase(logs_.begin());
    }

    DebugLog log;
    log.pc = pc;
    log.op_code = opcode;
    log.op_name = opcode_name;
    log.gas = gas;
    log.gas_cost = metrics_[opcode].gas_cost;
    log.depth = execution_state.msg->depth + 1;
    log.stack_height = stack_height;

    if (!config_.disable_stack) {
        output_stack(log.stack, stack_top, stack_height);
    }
    if (!config_.disable_memory) {
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

void DebugTracer::on_precompiled_run(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    SILK_DEBUG << "DebugTracer::on_precompiled_run:"
               << " status: " << result.status_code;

    if (logs_.size() > 1) {
        flush_logs();
    }
}

void DebugTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];

        insert_error(log, result.status_code);

        switch (result.status_code) {
            case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
            case evmc_status_code::EVMC_INVALID_INSTRUCTION:
            case evmc_status_code::EVMC_STACK_OVERFLOW:
            case evmc_status_code::EVMC_STACK_UNDERFLOW:
                if (log.op_name) {
                    log.gas_cost = result.gas_cost;
                } else {
                    log.gas_cost = 0;
                }
                break;

            case evmc_status_code::EVMC_OUT_OF_GAS:
                if (log.op_code != OP_CALLCODE) {
                    log.gas_cost = result.gas_cost;
                }
                break;

            default:
                if (log.op_code == OP_CALL || log.op_code == OP_CALLCODE || log.op_code == OP_STATICCALL || log.op_code == OP_DELEGATECALL || log.op_code == OP_CREATE || log.op_code == OP_CREATE2) {
                    log.gas_cost += result.gas_cost;
                } else {
                    log.gas_cost = log.gas_cost;
                }
                break;
        }

        /* EVM WA: EVMONE add OP_STOP at the end of tx if not present but doesn't notify to the tracer. Add sw to add STOP to the op list */
        if (result.status_code == EVMC_SUCCESS && last_opcode_ && last_opcode_ != OP_SELFDESTRUCT && last_opcode_ != OP_RETURN && last_opcode_ != OP_STOP) {
            DebugLog newlog;
            newlog.pc = log.pc + 1;
            newlog.op_name = get_opcode_name(opcode_names_, OP_STOP);
            newlog.op_code = OP_STOP;
            newlog.gas = log.gas - log.gas_cost;
            newlog.gas_cost = 0;
            newlog.depth = log.depth;
            newlog.memory = log.memory;
            logs_.push_back(newlog);
        }
    }

    if (logs_.size() > 1) {
        flush_logs();
    }

    SILK_DEBUG << "on_execution_end:"
               << " result.status_code: " << result.status_code
               << " gas_left: " << std::dec << result.gas_left
               << " gas_cost: " << std::dec << result.gas_cost;
}

void DebugTracer::flush_logs() {
    for (const auto& log : logs_) {
        write_log(log);
    }
    logs_.clear();
}

void AccountTracer::on_execution_end(const evmc_result& /*result*/, const silkworm::IntraBlockState& intra_block_state) noexcept {
    nonce_ = intra_block_state.get_nonce(address_);
    balance_ = intra_block_state.get_balance(address_);
    code_hash_ = intra_block_state.get_code_hash(address_);
    code_ = intra_block_state.get_code(address_);
}

void DebugTracer::write_log(const DebugLog& log) {
    stream_.open_object();
    stream_.write_field("depth", log.depth);
    stream_.write_field("gas", log.gas);
    stream_.write_field("gasCost", log.gas_cost);
    if (log.op_name) {
        stream_.write_field("op", log.op_name.value());
    } else {
        stream_.write_field("op", "opcode " + get_opcode_hex(log.op_code) + " not defined");
    }
    stream_.write_field("pc", log.pc);

    if (!config_.disable_stack) {
        stream_.write_field("stack");
        stream_.open_array();
        for (const auto& item : log.stack) {
            stream_.write_entry(item);
        }
        stream_.close_array();
    }
    if (!config_.disable_memory) {
        stream_.write_field("memory");
        stream_.open_array();
        for (const auto& item : log.memory) {
            const size_t len = 64;
            const auto data = item.data();
            for (size_t start = 0; start < item.size(); start += len) {
                stream_.write_entry({data + start, len});
            }
        }
        stream_.close_array();
    }
    if (!config_.disable_storage && !log.storage.empty()) {
        stream_.write_field("storage");
        stream_.open_object();
        for (const auto& entry : log.storage) {
            stream_.write_field(entry.first, entry.second);
        }
        stream_.close_object();
    }

    if (!log.error.empty()) {
        stream_.write_field("error", log.error);
    }

    stream_.close_object();
}

Task<void> DebugExecutor::trace_block(json::Stream& stream, const ChainStorage& storage, BlockNum block_num) {
    const auto block_with_hash = co_await rpc::core::read_block_by_number(block_cache_, storage, block_num);
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

Task<void> DebugExecutor::trace_call(json::Stream& stream, const BlockNumOrHash& block_num_or_hash, const ChainStorage& storage, const Call& call, bool is_latest_block) {
    const auto block_with_hash = co_await rpc::core::read_block_by_block_num_or_hash(block_cache_, storage, tx_, block_num_or_hash);
    if (!block_with_hash) {
        co_return;
    }
    rpc::Transaction transaction{call.to_transaction()};

    if (config_.tx_index) {
        const auto tx_index = static_cast<size_t>(config_.tx_index.value());
        if (tx_index > block_with_hash->block.transactions.size()) {
            std::ostringstream oss;
            oss << "TxIndex " << tx_index << " greater than #tnx in block " << block_num_or_hash;
            const Error error{-32000, oss.str()};
            stream.write_json_field("error", error);

            co_return;
        }
    }

    const auto& block = block_with_hash->block;
    const auto block_num = block.header.number + (config_.tx_index ? 0 : 1);
    const auto index = config_.tx_index ? config_.tx_index.value() : 0;
    // trace_call semantics: we must execute the call from the state at the end of the given block, so we pass block.header.number + 1
    co_await execute(stream, storage, block_num, block, transaction, index, is_latest_block);

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
        const auto block_num = block.header.number;

        // trace_transaction semantics: we must execute the txn from the state at the current block
        co_await execute(stream, storage, block_num, block, transaction, gsl::narrow<int32_t>(transaction.transaction_index));
    }

    co_return;
}

Task<void> DebugExecutor::trace_call_many(json::Stream& stream, const ChainStorage& storage, const Bundles& bundles, const SimulationContext& context, bool is_latest_block) {
    const auto block_with_hash = co_await rpc::core::read_block_by_block_num_or_hash(block_cache_, storage, tx_, context.block_num);
    if (!block_with_hash) {
        co_return;
    }
    auto transaction_index = context.transaction_index;
    if (transaction_index == -1) {
        transaction_index = static_cast<std::int32_t>(block_with_hash->block.transactions.size());
    }

    stream.write_field("result");
    stream.open_array();
    co_await execute(stream, storage, block_with_hash, bundles, transaction_index, is_latest_block);
    stream.close_array();

    co_return;
}

Task<void> DebugExecutor::execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block) {
    auto block_num = block.header.number;
    const auto& transactions = block.transactions;

    SILK_DEBUG << "execute: block_num: " << block_num << " #txns: " << transactions.size() << " config: " << config_;

    const auto chain_config = co_await storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;

    execution::StateFactory state_factory{tx_};
    const auto txn_id = co_await tx_.user_txn_id_at(block_num);

    co_await async_task(workers_.executor(), [&]() -> void {
        auto state = state_factory.create_state(current_executor, storage, txn_id);
        EVMExecutor executor{block, chain_config, workers_, state};

        bool refunds = !config_.no_refunds;

        for (std::uint64_t idx = 0; idx < transactions.size(); ++idx) {
            rpc::Transaction txn{block.transactions[idx]};
            SILK_DEBUG << "processing transaction: idx: " << idx << " txn: " << txn;

            auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

            stream.open_object();
            stream.write_field("result");
            stream.open_object();
            stream.write_field("structLogs");
            stream.open_array();

            Tracers tracers{debug_tracer};
            const auto execution_result = executor.call(txn, tracers, refunds);

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

// used by unit-test
Task<void> DebugExecutor::execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block, const Call& call) {
    rpc::Transaction transaction{call.to_transaction()};

    auto transaction_index = static_cast<std::int32_t>(block.transactions.size());

    co_await execute(stream, storage, block.header.number + 1, block, transaction, transaction_index);
    co_return;
}

Task<void> DebugExecutor::execute(
    json::Stream& stream,
    const ChainStorage& storage,
    BlockNum block_num,
    const silkworm::Block& block,
    const Transaction& transaction,
    int32_t index,
    bool is_latest_block) {
    SILK_TRACE << "DebugExecutor::execute: "
               << " block_num: " << block_num
               << " transaction: {" << transaction << "}"
               << " index: " << std::dec << index
               << " config: " << config_;

    const auto chain_config = co_await storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;

    // We must do the execution at the state after the txn identified by the given index within the given block
    // at the state after the block identified by the given block_num
    std::optional<TxnId> txn_id;
    if (!is_latest_block) {
        txn_id = co_await tx_.user_txn_id_at(block_num, static_cast<uint32_t>(index));
    }

    co_await async_task(workers_.executor(), [&]() {
        execution::StateFactory state_factory{tx_};
        const auto state = state_factory.create_state(current_executor, storage, txn_id);

        EVMExecutor executor{block, chain_config, workers_, state};

        auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);

        stream.write_field("result");
        stream.open_object();

        stream.write_field("structLogs");
        stream.open_array();

        bool refunds = !config_.no_refunds;
        Tracers tracers{debug_tracer};
        const auto execution_result = executor.call(transaction, tracers, refunds);

        debug_tracer->flush_logs();
        stream.close_array();

        SILK_DEBUG << "debug return: " << execution_result.error_message();

        if (!execution_result.pre_check_error) {
            stream.write_json_field("failed", !execution_result.success());
            stream.write_field("gas", transaction.gas_limit - execution_result.gas_left);
            stream.write_field("returnValue", silkworm::to_hex(execution_result.data));
        }
        stream.close_object();

        if (execution_result.pre_check_error) {
            const Error error{-32000, "tracing failed: " + execution_result.pre_check_error.value()};
            stream.write_json_field("error", error);
        }
    });

    co_return;
}

Task<void> DebugExecutor::execute(
    json::Stream& stream,
    const ChainStorage& storage,
    std::shared_ptr<BlockWithHash> block_with_hash,
    const Bundles& bundles,
    int32_t transaction_index,
    bool is_latest_block) {
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

    // We must do the execution at the state after the txn identified by transaction_with_block param in the same block
    // at the state of the block identified by the given block_num, i.e. at the start of the block (block_num)
    execution::StateFactory state_factory{tx_};

    std::optional<TxnId> txn_id;
    if (!is_latest_block) {
        txn_id = co_await tx_.user_txn_id_at(block.header.number, static_cast<uint32_t>(transaction_index));
    }

    co_await async_task(workers_.executor(), [&]() {
        auto state = state_factory.create_state(current_executor, storage, txn_id);
        EVMExecutor executor{block, chain_config, workers_, state};

        for (const auto& bundle : bundles) {
            const auto& block_override = bundle.block_override;

            rpc::Block block_context{{block_with_hash}};
            if (block_override.block_num) {
                block_context.block_with_hash->block.header.number = block_override.block_num.value();
            }
            if (block_override.coin_base) {
                block_context.block_with_hash->block.header.beneficiary = block_override.coin_base.value();
            }
            if (block_override.timestamp) {
                block_context.block_with_hash->block.header.timestamp = block_override.timestamp.value();
            }
            if (block_override.difficulty) {
                block_context.block_with_hash->block.header.difficulty = block_override.difficulty.value();
            }
            if (block_override.gas_limit) {
                block_context.block_with_hash->block.header.gas_limit = block_override.gas_limit.value();
            }
            if (block_override.base_fee) {
                block_context.block_with_hash->block.header.base_fee_per_gas = block_override.base_fee;
            }

            stream.open_array();
            bool refunds = !config_.no_refunds;

            for (const auto& call : bundle.transactions) {
                silkworm::Transaction txn{call.to_transaction()};

                stream.open_object();
                stream.write_field("structLogs");
                stream.open_array();

                auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);
                Tracers tracers{debug_tracer};

                const auto execution_result = executor.call(txn, tracers, refunds);

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
