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

#include "estimate_gas_oracle.hpp"

#include <string>

#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/core/override_state.hpp>

namespace silkworm::rpc {

Task<intx::uint256> EstimateGasOracle::estimate_gas(const Call& call, const silkworm::Block& block, std::optional<TxnId> txn_id) {
    SILK_DEBUG << "EstimateGasOracle::estimate_gas called";

    const auto block_num = block.header.number;

    uint64_t hi = 0;
    uint64_t lo;

    if (call.gas.value_or(0) >= kTxGas) {
        SILK_DEBUG << "Set gas limit using call args: " << call.gas.value_or(0);
        hi = call.gas.value();
    } else {
        const auto header = co_await block_header_provider_(block_num);
        if (!header) {
            co_return 0;
        }
        hi = header->gas_limit;
        SILK_DEBUG << "Set gas limit using block: " << header->gas_limit;
    }

    if (hi > kGasCap) {
        SILK_WARN << "caller gas above allowance, capping: requested " << hi << ", cap " << kGasCap;
        hi = kGasCap;
    }

    std::optional<intx::uint256> gas_price = call.gas_price;
    if (gas_price && gas_price != 0) {
        evmc::address from = call.from.value_or(evmc::address{0});

        std::optional<silkworm::Account> account{co_await account_reader_(from, txn_id)};

        intx::uint256 balance = account->balance;
        SILK_DEBUG << "balance for address " << from << ": 0x" << intx::hex(balance);
        if (call.value.value_or(0) > balance) {
            // TODO(sixtysixter) what is the right error code?
            throw EstimateGasException{-32000, "insufficient funds for transfer"};
        }
        auto available = balance - call.value.value_or(0);
        auto allowance = available / *gas_price;
        SILK_DEBUG << "allowance: " << allowance << ", available: 0x" << intx::hex(available) << ", balance: 0x" << intx::hex(balance);
        if (hi > allowance) {
            SILK_WARN << "gas estimation capped by limited funds: original " << hi
                      << ", balance 0x" << intx::hex(balance)
                      << ", sent " << intx::hex(call.value.value_or(0))
                      << ", gasprice " << intx::hex(*gas_price)
                      << ", allowance " << allowance;
            hi = uint64_t{allowance};
        }
    }

    auto this_executor = co_await boost::asio::this_coro::executor;

    execution::StateFactory state_factory{transaction_};

    auto exec_result = co_await async_task(workers_.executor(), [&]() -> ExecutionResult {
        auto state = state_factory.make(this_executor, storage_, txn_id);

        ExecutionResult result{evmc_status_code::EVMC_SUCCESS};
        silkworm::Transaction transaction{call.to_transaction()};

        auto state_overrides = std::make_shared<state::OverrideState>(*state, accounts_overrides_);
        EVMExecutor executor{block, config_, workers_, state_overrides};
        transaction.gas_limit = hi;
        result = try_execution(executor, transaction);
        if (!result.success()) {
            return result;
        }

        // Assuming a contract can freely run all the instructions, we have
        // the true amount of gas it wants to consume to execute fully.
        // We want to ensure that the gas used doesn't fall below this
        auto true_gas = result.gas_used.value_or(0);
        uint64_t refund = result.gas_refund.value_or(0);
        lo = std::min(true_gas + refund - 1, kTxGas - 1);

        SILK_DEBUG << "hi: " << hi << ", lo: " << lo;

        while (lo + 1 < hi) {
            state_overrides = std::make_shared<state::OverrideState>(*state, accounts_overrides_);
            EVMExecutor curr_executor{block, config_, workers_, state_overrides};
            auto mid = (hi + lo) / 2;
            transaction.gas_limit = mid;
            result = try_execution(curr_executor, transaction);
            if (result.pre_check_error_code) {
                break;
            }
            if (!result.success() || result.gas_used.value_or(0) < true_gas) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        result.status_code = evmc_status_code::EVMC_SUCCESS;

        SILK_DEBUG << "EstimateGasOracle::estimate_gas returns " << hi;

        return result;
    });

    if (!exec_result.success()) {
        if (exec_result.status_code == evmc_status_code::EVMC_OUT_OF_GAS) {
            std::string error_msg = "gas required exceeds allowance (" + std::to_string(hi) + ")";
            throw EstimateGasException{-32000, error_msg};
        }
        throw_exception(exec_result);
    }
    co_return hi;
}

ExecutionResult EstimateGasOracle::try_execution(EVMExecutor& executor, const silkworm::Transaction& transaction) {
    return executor.call(transaction);
}

void EstimateGasOracle::throw_exception(ExecutionResult& result) {
    if (result.pre_check_error) {
        SILK_DEBUG << "result error " << result.pre_check_error.value();
        throw EstimateGasException{-32000, *result.pre_check_error};
    }
    auto error_message = result.error_message();
    SILK_DEBUG << "result message: " << error_message << ", code " << *result.status_code;
    if (result.data.empty()) {
        throw EstimateGasException{-32000, error_message};
    }
    throw EstimateGasException{3, error_message, result.data};
}
}  // namespace silkworm::rpc
