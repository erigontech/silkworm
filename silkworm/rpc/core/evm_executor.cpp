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

#include "evm_executor.hpp"

#include <optional>
#include <string>
#include <utility>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/types/transaction.hpp>

#include "silkworm/core/execution/processor.hpp"

namespace silkworm::rpc {

std::string ExecutionResult::error_message(bool full_error) const {
    if (pre_check_error) {
        return *pre_check_error;
    }
    if (error_code) {
        return silkworm::rpc::EVMExecutor::get_error_message(*error_code, data, full_error);
    }
    return "";
}

static Bytes build_abi_selector(const std::string& signature) {
    const auto signature_hash = hash_of(string_view_to_byte_view(signature));
    return {std::begin(signature_hash.bytes), std::begin(signature_hash.bytes) + 4};
}

static std::optional<std::string> decode_error_reason(const Bytes& error_data) {
    static const Bytes kRevertSelector = build_abi_selector("Error(string)");
    static constexpr size_t kAbiStringOffsetSize{32};

    if (error_data.size() < kRevertSelector.size() || error_data.substr(0, kRevertSelector.size()) != kRevertSelector) {
        return std::nullopt;
    }

    ByteView encoded_msg{error_data.data() + kRevertSelector.size(), error_data.size() - kRevertSelector.size()};
    SILK_TRACE << "decode_error_reason size: " << encoded_msg.size() << " error_message: " << to_hex(encoded_msg);
    if (encoded_msg.size() < kAbiStringOffsetSize) {
        return std::nullopt;
    }

    const auto offset_uint256{intx::be::unsafe::load<intx::uint256>(encoded_msg.data())};
    SILK_TRACE << "decode_error_reason offset_uint256: " << intx::to_string(offset_uint256);
    const auto offset = static_cast<uint64_t>(offset_uint256);
    if (encoded_msg.size() < kAbiStringOffsetSize + offset) {
        return std::nullopt;
    }

    const uint64_t message_offset{kAbiStringOffsetSize + offset};
    const auto length_uint256{intx::be::unsafe::load<intx::uint256>(encoded_msg.data() + offset)};
    SILK_TRACE << "decode_error_reason length_uint256: " << intx::to_string(length_uint256);
    const auto length = static_cast<uint64_t>(length_uint256);
    if (encoded_msg.size() < message_offset + length) {
        return std::nullopt;
    }

    return std::string{std::begin(encoded_msg) + message_offset, std::begin(encoded_msg) + message_offset + length};
}

std::string EVMExecutor::get_error_message(int64_t error_code, const Bytes& error_data, bool full_error) {
    SILK_DEBUG << "EVMExecutor::get_error_message error_data: " << to_hex(error_data);

    std::string error_message;
    switch (error_code) {
        case evmc_status_code::EVMC_FAILURE:
            error_message = "execution failed";
            break;
        case evmc_status_code::EVMC_REVERT:
            error_message = "execution reverted";
            break;
        case evmc_status_code::EVMC_OUT_OF_GAS:
            error_message = "out of gas";
            break;
        case evmc_status_code::EVMC_INVALID_INSTRUCTION:
            error_message = "invalid instruction";
            break;
        case evmc_status_code::EVMC_UNDEFINED_INSTRUCTION:
            error_message = "invalid opcode";
            break;
        case evmc_status_code::EVMC_STACK_OVERFLOW:
            error_message = "stack overflow";
            break;
        case evmc_status_code::EVMC_STACK_UNDERFLOW:
            error_message = "stack underflow";
            break;
        case evmc_status_code::EVMC_BAD_JUMP_DESTINATION:
            error_message = "invalid jump destination";
            break;
        case evmc_status_code::EVMC_INVALID_MEMORY_ACCESS:
            error_message = "invalid memory access";
            break;
        case evmc_status_code::EVMC_CALL_DEPTH_EXCEEDED:
            error_message = "call depth exceeded";
            break;
        case evmc_status_code::EVMC_STATIC_MODE_VIOLATION:
            error_message = "static mode violation";
            break;
        case evmc_status_code::EVMC_PRECOMPILE_FAILURE:
            error_message = "precompile failure";
            break;
        case evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE:
            error_message = "contract validation failure";
            break;
        case evmc_status_code::EVMC_ARGUMENT_OUT_OF_RANGE:
            error_message = "argument out of range";
            break;
        case evmc_status_code::EVMC_WASM_UNREACHABLE_INSTRUCTION:
            error_message = "wasm unreachable instruction";
            break;
        case evmc_status_code::EVMC_WASM_TRAP:
            error_message = "wasm trap";
            break;
        case evmc_status_code::EVMC_INSUFFICIENT_BALANCE:
            error_message = "insufficient balance";
            break;
        case evmc_status_code::EVMC_INTERNAL_ERROR:
            error_message = "internal error";
            break;
        case evmc_status_code::EVMC_REJECTED:
            error_message = "execution rejected";
            break;
        case evmc_status_code::EVMC_OUT_OF_MEMORY:
            error_message = "out of memory";
            break;
        default:
            error_message = "unknown error code";
    }

    if (full_error) {
        const auto error_reason{decode_error_reason(error_data)};
        if (error_reason) {
            error_message += ": " + *error_reason;
        }
    }
    SILK_DEBUG << "EVMExecutor::get_error_message error_message: " << error_message;
    return error_message;
}

void EVMExecutor::reset() {
    execution_processor_.reset();
}

ExecutionResult convert_validated_precheck(const ValidationResult& result, const Block& block, const silkworm::Transaction& txn, const EVM& evm) {
    std::string from = address_to_hex(*txn.sender());
    switch (result) {
        case ValidationResult::kMaxPriorityFeeGreaterThanMax: {
            std::string error = "tip higher than fee cap: address " + from + ", tip: " + intx::to_string(txn.max_priority_fee_per_gas) + " gasFeeCap: " +
                                intx::to_string(txn.max_fee_per_gas);
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kTipHigherThanFeeCap};
        }
        case ValidationResult::kMaxFeeLessThanBase: {
            std::string error = "fee cap less than block base fee: address " + from + ", gasFeeCap: " +
                                intx::to_string(txn.max_fee_per_gas) + " baseFee: " + intx::to_string(*block.header.base_fee_per_gas);
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kFeeCapLessThanBlockFeePerGas};
        }
        case ValidationResult::kIntrinsicGas: {
            const intx::uint128 g0{protocol::intrinsic_gas(txn, evm.revision())};
            std::string error = "intrinsic gas too low: have " + std::to_string(txn.gas_limit) + ", want " + intx::to_string(g0);
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kIntrinsicGasTooLow};
        }
        case ValidationResult::kWrongBlockGas: {
            std::string error = "internal failure: Cancun is active but ExcessBlobGas is nil";
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kInternalError};
        }
        case ValidationResult::kUnsupportedTransactionType: {
            std::string error = "eip-1559 transactions require london";
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kIsNotLondon};
        }
        default: {
            std::string error = "internal failure";
            return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kInternalError};
        }
    }
}

ExecutionResult convert_validated_funds(const Block& block, const silkworm::Transaction& txn, const EVM& evm, const intx::uint256& owned_funds) {
    std::string from = address_to_hex(*txn.sender());
    const intx::uint256 base_fee_per_gas{block.header.base_fee_per_gas.value_or(0)};

    const intx::uint256 effective_gas_price{txn.max_fee_per_gas >= base_fee_per_gas ? txn.effective_gas_price(base_fee_per_gas)
                                                                                    : txn.max_priority_fee_per_gas};
    const auto required_funds = protocol::compute_call_cost(txn, effective_gas_price, evm);
    intx::uint512 maximum_cost = required_funds;
    if (txn.type != TransactionType::kLegacy && txn.type != TransactionType::kAccessList) {
        maximum_cost = txn.maximum_gas_cost();
    }
    std::string error = "insufficient funds for gas * price + value: address " + from + " have " + intx::to_string(owned_funds) + " want " + intx::to_string(maximum_cost + txn.value);
    return {std::nullopt, txn.gas_limit, {}, error, PreCheckErrorCode::kInsufficientFunds};
}

ExecutionResult EVMExecutor::call(
    const silkworm::Block& block,
    const silkworm::Transaction& txn,
    const Tracers& tracers,
    bool refund,
    bool bailout) {
    auto& evm = execution_processor_.evm();

    auto& svc = use_service<AnalysisCacheService>(workers_);

    evm.analysis_cache = svc.get_analysis_cache();
    evm.beneficiary = rule_set_->get_beneficiary(block.header);
    evm.transfer = rule_set_->transfer_func();
    evm.bailout = bailout;

    if (!txn.sender()) {
        return {std::nullopt, txn.gas_limit, Bytes{}, "malformed transaction: cannot recover sender"};
    }

    if (const auto result = protocol::validate_call_precheck(txn, evm);
        result != ValidationResult::kOk) {
        return convert_validated_precheck(result, block, txn, evm);
    }

    const auto owned_funds = execution_processor_.intra_block_state().get_balance(*txn.sender());

    if (const auto result = protocol::validate_call_funds(txn, evm, owned_funds);
        !bailout && result != ValidationResult::kOk) {
        return convert_validated_funds(block, txn, evm, owned_funds);
    }

    const auto result = execution_processor_.call(txn, tracers, bailout, refund);

    ExecutionResult exec_result{result.status, result.gas_left, result.data};

    SILK_DEBUG << "EVMExecutor::call call_result: " << exec_result.error_message() << " #data: " << exec_result.data.size() << " end";

    return exec_result;
}

ExecutionResult EVMExecutor::call_with_receipt(
    const silkworm::Block& block,
    const silkworm::Transaction& txn,
    Receipt& receipt,
    const Tracers& tracers,
    bool refund,
    bool gas_bailout) {
    SILK_DEBUG << "EVMExecutor::call: blockNumber: " << block.header.number << " gas_limit: " << txn.gas_limit << " refund: " << refund
               << " gas_bailout: " << gas_bailout << " transaction: " << rpc::Transaction{txn};

    const auto exec_result = call(block, txn, tracers, refund, gas_bailout);

    auto& logs = execution_processor_.intra_block_state().logs();

    receipt.success = exec_result.success();
    receipt.bloom = logs_bloom(logs);
    receipt.gas_used = txn.gas_limit - exec_result.gas_left;
    receipt.type = txn.type;
    for (auto& log : logs) {
        Log rpc_log;
        rpc_log.address = log.address;
        rpc_log.data = std::move(log.data);
        rpc_log.topics = std::move(log.topics);
        receipt.logs.push_back(std::move(rpc_log));
    }

    SILK_DEBUG << "EVMExecutor::call call_result: " << exec_result.error_message() << " #data: " << exec_result.data.size() << " end";

    return exec_result;
}

Task<ExecutionResult> EVMExecutor::call(
    const silkworm::ChainConfig& config,
    const ChainStorage& chain_storage,
    WorkerPool& workers,
    const silkworm::Block& block,
    const silkworm::Transaction& txn,
    const TxnId txn_id,
    StateFactory state_factory,
    const Tracers& tracers,
    bool refund,
    bool gas_bailout) {
    auto this_executor = co_await boost::asio::this_coro::executor;
    const auto execution_result = co_await async_task(workers.executor(), [&]() -> ExecutionResult {
        auto state = state_factory(this_executor, txn_id, chain_storage);
        EVMExecutor executor{block, config, workers, state};
        return executor.call(block, txn, tracers, refund, gas_bailout);
    });
    co_return execution_result;
}

}  // namespace silkworm::rpc
