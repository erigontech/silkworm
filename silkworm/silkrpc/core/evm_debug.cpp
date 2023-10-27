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

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/instructions.h>
#include <evmone/execution_state.hpp>
#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/cached_chain.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
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

std::string uint256_to_hex(const evmone::uint256& x) {
    std::stringstream ss;
    ss << "0x";

    bool leading_zeros = true;
    const uint64_t* px = &x[0];
    for (int i = 3; i >= 0; i--) {
        if (px[i] == 0) {
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

std::string get_opcode_name(const char* const* names, std::uint8_t opcode) {
    const auto name = names[opcode];
    return (name != nullptr) ? name : "opcode 0x" + evmc::hex(opcode) + " not defined";
}

static std::string EMPTY_MEMORY(64, '0');

void output_stack(std::vector<std::string>& vect, const evmone::uint256* stack, uint32_t stack_size) {
    vect.reserve(stack_size);
    for (int i = int(stack_size - 1); i >= 0; --i) {
        vect.push_back(uint256_to_hex(stack[-i]));
    }
}

void output_memory(std::vector<std::string>& vect, const evmone::Memory& memory) {
    const std::size_t len = 32;
    vect.reserve(memory.size() / len);

    const auto data = memory.data();
    for (std::size_t start = 0; start < memory.size(); start += len) {
        vect.push_back(silkworm::to_hex({data + start, len}));
    }
}

void insert_error(DebugLog& log, evmc_status_code status_code) {
    switch (status_code) {
        case evmc_status_code::EVMC_FAILURE:
        case evmc_status_code::EVMC_OUT_OF_GAS:
            log.error = true;
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
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
    const evmc::address recipient(msg.recipient);
    const evmc::address sender(msg.sender);
    SILK_DEBUG << "on_execution_start: gas: " << std::dec << msg.gas
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
                log.gas_cost = log.gas - gas;
            }
            if (!config_.disableMemory) {
                auto& memory = log.memory;
                for (std::size_t idx = memory.size(); idx < current_memory.size(); idx++) {
                    memory.push_back(EMPTY_MEMORY);
                }
            }
        } else if (depth == execution_state.msg->depth) {
            log.gas_cost = log.gas - gas;
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
    log.gas = gas;
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
    SILK_DEBUG << "DebugTracer::on_precompiled_run:"
               << " status: " << result.status_code
               << ", gas: " << std::dec << gas;

    gas_on_precompiled_ = gas;
}

void DebugTracer::on_execution_end(const evmc_result& result, const silkworm::IntraBlockState& /*intra_block_state*/) noexcept {
    if (!logs_.empty()) {
        auto& log = logs_[logs_.size() - 1];

        insert_error(log, result.status_code);

        switch (result.status_code) {
            case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
                log.gas_cost = 0;
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

    SILK_DEBUG << "on_execution_end:"
               << " result.status_code: " << result.status_code
               << " start_gas: " << std::dec << start_gas_
               << " gas_left: " << std::dec << result.gas_left;
}

void DebugTracer::flush_logs() {
    for (const auto& log : logs_) {
        write_log(log);
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
            stream_.write_entry(item);
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
        stream_.write_field("error", "{}");
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
    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, storage, database_reader_, bnoh);
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
        const auto& block = tx_with_block->block_with_hash.block;
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
    const auto block_with_hash = co_await rpc::core::read_block_by_number_or_hash(block_cache_, storage, database_reader_, context.block_number);
    if (!block_with_hash) {
        co_return;
    }
    auto transaction_index = context.transaction_index;
    if (transaction_index == -1) {
        transaction_index = static_cast<std::int32_t>(block_with_hash->block.transactions.size());
    }

    stream.write_field("result");
    stream.open_array();
    co_await execute(stream, storage, *block_with_hash, bundles, transaction_index);
    stream.close_array();

    co_return;
}

Task<void> DebugExecutor::execute(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block) {
    auto block_number = block.header.number;
    const auto& transactions = block.transactions;

    SILK_DEBUG << "execute: block_number: " << block_number << " #txns: " << transactions.size() << " config: " << config_;

    const auto chain_config_ptr = co_await storage.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");
    auto current_executor = co_await boost::asio::this_coro::executor;

    co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(void)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, storage, block_number - 1);
                EVMExecutor executor{*chain_config_ptr, workers_, state};

                for (std::uint64_t idx = 0; idx < transactions.size(); idx++) {
                    rpc::Transaction txn{block.transactions[idx]};
                    if (!txn.from) {
                        txn.recover_sender();
                    }
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
                    stream.close_object();
                }
                boost::asio::post(current_executor, [self = std::move(self)]() mutable {
                    self.complete();
                });
            });
        },
        boost::asio::use_awaitable);

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

    const auto chain_config_ptr = co_await storage.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");
    auto current_executor = co_await boost::asio::this_coro::executor;

    co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(void)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, storage, block_number);
                EVMExecutor executor{*chain_config_ptr, workers_, state};

                for (auto idx{0}; idx < index; idx++) {
                    silkworm::Transaction txn{block.transactions[std::size_t(idx)]};

                    if (!txn.from) {
                        txn.recover_sender();
                    }
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
                boost::asio::post(current_executor, [self = std::move(self)]() mutable {
                    self.complete();
                });
            });
        },
        boost::asio::use_awaitable);

    co_return;
}

Task<void> DebugExecutor::execute(
    json::Stream& stream,
    const ChainStorage& storage,
    const silkworm::BlockWithHash& block_with_hash,
    const Bundles& bundles,
    int32_t transaction_index) {
    const auto& block = block_with_hash.block;
    const auto& block_transactions = block.transactions;

    SILK_TRACE << "DebugExecutor::execute: "
               << " block number: " << block.header.number
               << " txns in block: " << block_transactions.size()
               << " bundles: [" << bundles << "]"
               << " transaction_index: " << std::dec << transaction_index
               << " config: " << config_;

    const auto chain_config_ptr = co_await storage.read_chain_config();
    ensure(chain_config_ptr.has_value(), "cannot read chain config");

    auto current_executor = co_await boost::asio::this_coro::executor;
    co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(void)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = tx_.create_state(current_executor, database_reader_, storage, block.header.number);
                EVMExecutor executor{*chain_config_ptr, workers_, state};

                for (auto idx{0}; idx < transaction_index; idx++) {
                    silkworm::Transaction txn{block_transactions[std::size_t(idx)]};

                    if (!txn.from) {
                        txn.recover_sender();
                    }

                    executor.call(block, txn);
                }
                executor.reset();

                for (const auto& bundle : bundles) {
                    const auto& block_override = bundle.block_override;

                    rpc::Block blockContext{{block_with_hash.block}};
                    if (block_override.block_number) {
                        blockContext.block.header.number = block_override.block_number.value();
                    }
                    if (block_override.coin_base) {
                        blockContext.block.header.beneficiary = block_override.coin_base.value();
                    }
                    if (block_override.timestamp) {
                        blockContext.block.header.timestamp = block_override.timestamp.value();
                    }
                    if (block_override.difficulty) {
                        blockContext.block.header.difficulty = block_override.difficulty.value();
                    }
                    if (block_override.gas_limit) {
                        blockContext.block.header.gas_limit = block_override.gas_limit.value();
                    }
                    if (block_override.base_fee) {
                        blockContext.block.header.base_fee_per_gas = block_override.base_fee;
                    }

                    stream.open_array();

                    for (const auto& call : bundle.transactions) {
                        silkworm::Transaction txn{call.to_transaction()};

                        stream.open_object();
                        stream.write_field("structLogs");
                        stream.open_array();

                        auto debug_tracer = std::make_shared<debug::DebugTracer>(stream, config_);
                        Tracers tracers{debug_tracer};

                        const auto execution_result = executor.call(blockContext.block, txn, tracers, /* refund */ false, /* gasBailout */ false);

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
                boost::asio::post(current_executor, [self = std::move(self)]() mutable {
                    self.complete();
                });
            });
        },
        boost::asio::use_awaitable);

    co_return;
}

}  // namespace silkworm::rpc::debug
