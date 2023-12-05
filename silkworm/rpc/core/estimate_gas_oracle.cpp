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

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/blocks.hpp>

namespace silkworm::rpc {

Task<intx::uint256> EstimateGasOracle::estimate_gas(const Call& call, const silkworm::Block& block) {
    SILK_DEBUG << "EstimateGasOracle::estimate_gas called";

    auto block_number = block.header.number;

    uint64_t hi;
    uint64_t lo = kTxGas - 1;

    if (call.gas.value_or(0) >= kTxGas) {
        SILK_DEBUG << "Set HI with gas in args: " << call.gas.value_or(0);
        hi = call.gas.value();
    } else {
        const auto header = co_await block_header_provider_(block_number);
        if (!header) {
            throw EstimateGasException{-1, "invalid header"};
        }

        hi = header->gas_limit;
        SILK_DEBUG << "Evaluate HI with gas in block " << header->gas_limit;
    }

    intx::uint256 gas_price = call.gas_price.value_or(0);
    if (gas_price != 0) {
        evmc::address from = call.from.value_or(evmc::address{0});

        std::optional<silkworm::Account> account{co_await account_reader_(from, block_number + 1)};

        intx::uint256 balance = account->balance;
        SILK_DEBUG << "balance for address " << from << ": 0x" << intx::hex(balance);
        if (call.value.value_or(0) > balance) {
            // TODO(sixtysixter) what is the right error code?
            throw EstimateGasException{-1, "insufficient funds for transfer"};
        }
        auto available = balance - call.value.value_or(0);
        auto allowance = available / gas_price;
        SILK_DEBUG << "allowance: " << allowance << ", available: 0x" << intx::hex(available) << ", balance: 0x" << intx::hex(balance);
        if (hi > allowance) {
            SILK_WARN << "gas estimation capped by limited funds: original " << hi
                      << ", balance 0x" << intx::hex(balance)
                      << ", sent " << intx::hex(call.value.value_or(0))
                      << ", gasprice " << intx::hex(gas_price)
                      << ", allowance " << allowance;
            hi = uint64_t(allowance);
        }
    }

    if (hi > kGasCap) {
        SILK_WARN << "caller gas above allowance, capping: requested " << hi << ", cap " << kGasCap;
        hi = kGasCap;
    }
    auto cap = hi;

    SILK_DEBUG << "hi: " << hi << ", lo: " << lo << ", cap: " << cap;

    auto this_executor = co_await boost::asio::this_coro::executor;
    auto exec_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(ExecutionResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = transaction_.create_state(this_executor, tx_database_, storage_, block_number);
                EVMExecutor executor{config_, workers_, state};

                ExecutionResult result{evmc_status_code::EVMC_SUCCESS};
                silkworm::Transaction transaction{call.to_transaction()};
                while (lo + 1 < hi) {
                    auto mid = (hi + lo) / 2;
                    transaction.gas_limit = mid;

                    result = try_execution(executor, block, transaction);
                    if (result.success()) {
                        hi = mid;
                    } else {
                        lo = mid;
                        if (result.pre_check_error == std::nullopt) {
                            break;
                        }
                    }
                }

                if (hi == cap) {
                    transaction.gas_limit = hi;
                    result = try_execution(executor, block, transaction);
                    SILK_DEBUG << "HI == cap tested again with " << (result.error_code == evmc_status_code::EVMC_SUCCESS ? "succeed" : "failed");
                } else if (result.error_code == std::nullopt) {
                    result.pre_check_error = std::nullopt;
                    result.error_code = evmc_status_code::EVMC_SUCCESS;
                }

                SILK_DEBUG << "EstimateGasOracle::estimate_gas returns " << hi;

                boost::asio::post(this_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    if (exec_result.success() == false) {
        throw_exception(exec_result, cap);
    }
    co_return hi;
}

ExecutionResult EstimateGasOracle::try_execution(EVMExecutor& executor, const silkworm::Block& block, const silkworm::Transaction& transaction) {
    return executor.call(block, transaction);
}

void EstimateGasOracle::throw_exception(ExecutionResult& result, uint64_t cap) {
    if (result.pre_check_error) {
        SILK_DEBUG << "result error " << result.pre_check_error.value();
        throw EstimateGasException{-1, "gas required exceeds allowance (" + std::to_string(cap) + ")"};
    } else {
        auto error_message = result.error_message();
        SILK_DEBUG << "result message: " << error_message << ", code " << *result.error_code;
        if (result.data.empty()) {
            throw EstimateGasException{-32000, error_message};
        } else {
            throw EstimateGasException{3, error_message, result.data};
        }
    }
}
}  // namespace silkworm::rpc
