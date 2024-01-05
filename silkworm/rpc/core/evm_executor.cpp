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

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/local_state.hpp>
#include <silkworm/rpc/types/transaction.hpp>

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
    const auto signature_hash = hash_of(byte_view_of_string(signature));
    return {std::begin(signature_hash.bytes), std::begin(signature_hash.bytes) + 4};
}

static std::optional<std::string> decode_error_reason(const Bytes& error_data) {
    static const auto kRevertSelector{build_abi_selector("Error(string)")};
    static const auto kAbiStringOffsetSize{32};

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

uint64_t EVMExecutor::refund_gas(const EVM& evm, const silkworm::Transaction& txn, uint64_t gas_left, uint64_t gas_refund) {
    const evmc_revision rev{evm.revision()};
    const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? protocol::kMaxRefundQuotientLondon
                                                          : protocol::kMaxRefundQuotientFrontier};
    const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
    const uint64_t refund = gas_refund < max_refund ? gas_refund : max_refund;  // min
    gas_left += refund;

    const intx::uint256 base_fee_per_gas{evm.block().header.base_fee_per_gas.value_or(0)};
    SILK_DEBUG << "EVMExecutor::refund_gas txn.max_fee_per_gas: " << txn.max_fee_per_gas << " base_fee_per_gas: " << base_fee_per_gas;
    const intx::uint256 effective_gas_price{txn.max_fee_per_gas >= base_fee_per_gas ? txn.effective_gas_price(base_fee_per_gas)
                                                                                    : txn.max_priority_fee_per_gas};
    SILK_DEBUG << "EVMExecutor::refund_gas effective_gas_price: " << effective_gas_price;
    ibs_state_.add_to_balance(*txn.sender(), gas_left * effective_gas_price);
    return gas_left;
}

void EVMExecutor::reset() {
    ibs_state_.clear_journal_and_substate();
}

std::optional<std::string> EVMExecutor::pre_check(const EVM& evm, const silkworm::Transaction& txn, const intx::uint256& base_fee_per_gas, const intx::uint128& g0) {
    const evmc_revision rev{evm.revision()};

    if (rev >= EVMC_LONDON) {
        if (txn.max_fee_per_gas > 0 || txn.max_priority_fee_per_gas > 0) {
            if (txn.max_fee_per_gas < base_fee_per_gas) {
                const std::string from = address_to_hex(*txn.sender());
                const std::string error = "fee cap less than block base fee: address " + from + ", gasFeeCap: " +
                                          intx::to_string(txn.max_fee_per_gas) + " baseFee: " + intx::to_string(base_fee_per_gas);
                return error;
            }

            if (txn.max_fee_per_gas < txn.max_priority_fee_per_gas) {
                std::string from = address_to_hex(*txn.sender());
                std::string error = "tip higher than fee cap: address " + from + ", tip: " + intx::to_string(txn.max_priority_fee_per_gas) + " gasFeeCap: " +
                                    intx::to_string(txn.max_fee_per_gas);
                return error;
            }
        }
    }
    if (txn.gas_limit < g0) {
        std::string from = address_to_hex(*txn.sender());
        std::string error = "intrinsic gas too low: address " + from + ", have " + std::to_string(txn.gas_limit) + ", want " + intx::to_string(g0);
        return error;
    }
    return std::nullopt;
}

ExecutionResult EVMExecutor::call(
    const silkworm::Block& block,
    const silkworm::Transaction& txn,
    const Tracers& tracers,
    bool refund,
    bool gas_bailout) {
    SILK_DEBUG << "EVMExecutor::call: " << block.header.number << " gasLimit: " << txn.gas_limit << " refund: " << refund << " gasBailout: " << gas_bailout;
    SILK_DEBUG << "EVMExecutor::call: transaction: " << &txn;

    auto& svc = use_service<AnalysisCacheService>(workers_);
    EVM evm{block, ibs_state_, config_};
    evm.analysis_cache = svc.get_analysis_cache();
    evm.state_pool = svc.get_object_pool();
    evm.beneficiary = rule_set_->get_beneficiary(block.header);

    for (auto& tracer : tracers) {
        evm.add_tracer(*tracer);
    }

    if (!txn.sender()) {
        return {std::nullopt, txn.gas_limit, Bytes{}, "malformed transaction: cannot recover sender"};
    }
    ibs_state_.access_account(*txn.sender());

    const evmc_revision rev{evm.revision()};
    const intx::uint256 base_fee_per_gas{evm.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint128 g0{protocol::intrinsic_gas(txn, rev)};
    SILKWORM_ASSERT(g0 <= UINT64_MAX);  // true due to the precondition (transaction must be valid)

    const auto error = pre_check(evm, txn, base_fee_per_gas, g0);
    if (error) {
        Bytes data{};
        return {std::nullopt, txn.gas_limit, data, *error};
    }

    intx::uint256 want;
    if (txn.max_fee_per_gas > 0 || txn.max_priority_fee_per_gas > 0) {
        // This method should be called after check (max_fee and base_fee) present in pre_check() method
        const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
        want = txn.gas_limit * effective_gas_price;
    } else {
        want = 0;
    }
    const auto have = ibs_state_.get_balance(*txn.sender());
    if (have < want + txn.value) {
        if (!gas_bailout) {
            Bytes data{};
            std::string from = address_to_hex(*txn.sender());
            std::string msg = "insufficient funds for gas * price + value: address " + from + ", have " + intx::to_string(have) + ", want " + intx::to_string(want + txn.value);
            return {std::nullopt, txn.gas_limit, data, msg};
        }
    } else {
        ibs_state_.subtract_from_balance(*txn.sender(), want);
    }

    if (txn.to.has_value()) {
        ibs_state_.access_account(*txn.to);
        // EVM itself increments the nonce for contract creation
        ibs_state_.set_nonce(*txn.sender(), ibs_state_.get_nonce(*txn.sender()) + 1);
    }
    for (const AccessListEntry& ae : txn.access_list) {
        ibs_state_.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            ibs_state_.access_storage(ae.account, key);
        }
    }
    silkworm::CallResult result;
    try {
        SILK_DEBUG << "EVMExecutor::call execute on EVM txn: " << &txn << " g0: " << static_cast<uint64_t>(g0) << " start";
        result = evm.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0));
        SILK_DEBUG << "EVMExecutor::call execute on EVM txn: " << &txn << " gas_left: " << result.gas_left << " end";
    } catch (const std::exception& e) {
        SILK_ERROR << "exception: evm_execute: " << e.what() << "\n";
        std::string error_msg = "evm.execute: ";
        error_msg.append(e.what());
        return {std::nullopt, txn.gas_limit, /* data */ {}, error_msg};
    } catch (...) {
        SILK_ERROR << "exception: evm_execute: unexpected exception\n";
        return {std::nullopt, txn.gas_limit, /* data */ {}, "evm.execute: unknown exception"};
    }

    uint64_t gas_left = result.gas_left;
    const uint64_t gas_used{txn.gas_limit - refund_gas(evm, txn, result.gas_left, result.gas_refund)};
    if (refund) {
        gas_left = txn.gas_limit - gas_used;
    }

    // Reward the fee recipient
    const intx::uint256 priority_fee_per_gas{txn.max_fee_per_gas >= base_fee_per_gas ? txn.priority_fee_per_gas(base_fee_per_gas)
                                                                                     : txn.max_priority_fee_per_gas};
    SILK_DEBUG << "EVMExecutor::call evm.beneficiary: " << evm.beneficiary << " balance: " << priority_fee_per_gas * gas_used;
    ibs_state_.add_to_balance(evm.beneficiary, priority_fee_per_gas * gas_used);

    for (auto& tracer : evm.tracers()) {
        tracer.get().on_reward_granted(result, evm.state());
    }
    ibs_state_.finalize_transaction(rev);

    ExecutionResult exec_result{result.status, gas_left, result.data};

    SILK_DEBUG << "EVMExecutor::call call_result: " << exec_result.error_message() << " #data: " << exec_result.data.size() << " end";

    return exec_result;
}

Task<ExecutionResult> EVMExecutor::call(
    const silkworm::ChainConfig& config,
    const ChainStorage& chain_storage,
    boost::asio::thread_pool& workers,
    const silkworm::Block& block,
    const silkworm::Transaction& txn,
    StateFactory state_factory,
    const Tracers& tracers,
    bool refund,
    bool gas_bailout) {
    auto this_executor = co_await boost::asio::this_coro::executor;
    const auto execution_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(ExecutionResult)>(
        [&](auto& self) {
            boost::asio::post(workers, [&, self = std::move(self)]() mutable {
                auto state = state_factory(this_executor, block.header.number, chain_storage);
                EVMExecutor executor{config, workers, state};
                auto exec_result = executor.call(block, txn, tracers, refund, gas_bailout);
                boost::asio::post(this_executor, [exec_result, self = std::move(self)]() mutable {
                    self.complete(exec_result);
                });
            });
        },
        boost::asio::use_awaitable);
    co_return execution_result;
}

}  // namespace silkworm::rpc
