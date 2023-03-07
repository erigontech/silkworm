/*
    Copyright 2021 The Silkrpc Authors

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

#include <algorithm>
#include <string>
#include <utility>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkrpc::ego {

boost::asio::awaitable<intx::uint256> EstimateGasOracle::estimate_gas(const Call& call, uint64_t block_number) {
    SILKRPC_DEBUG << "EstimateGasOracle::estimate_gas called\n";

    std::uint64_t hi;
    std::uint64_t lo = kTxGas - 1;

    if (call.gas.value_or(0) >= kTxGas) {
        SILKRPC_DEBUG << "Set HI with gas in args: " << call.gas.value_or(0) << "\n";
        hi = call.gas.value();
    } else {
        const auto header = co_await block_header_provider_(block_number);
        hi = header.gas_limit;
        SILKRPC_DEBUG << "Evaluate HI with gas in block " << header.gas_limit << "\n";
    }

    intx::uint256 gas_price = call.gas_price.value_or(0);
    if (gas_price != 0) {
        evmc::address from = call.from.value_or(evmc::address{0});

        std::optional<silkworm::Account> account{co_await account_reader_(from, block_number + 1)};

        intx::uint256 balance = account->balance;
        SILKRPC_DEBUG << "balance for address 0x" << from << ": 0x" << intx::hex(balance) << "\n";
        if (call.value.value_or(0) > balance) {
            // TODO(sixtysixter) what is the right code?
            throw EstimateGasException{-1, "insufficient funds for transfer"};
        }
        auto available = balance - call.value.value_or(0);
        int64_t allowance = int64_t(available / gas_price);
        SILKRPC_DEBUG << "allowance: " << allowance << ", available: 0x" << intx::hex(available) << ", balance: 0x" << intx::hex(balance)  << "\n";
        if (hi > allowance) {
            SILKRPC_WARN << "gas estimation capped by limited funds: original " << hi
                << ", balance 0x" << intx::hex(balance)
                << ", sent" << intx::hex(call.value.value_or(0))
                << ", gasprice" << intx::hex(gas_price)
                << ", fundable" << allowance
                << "\n";
            hi = allowance;
        }
    }

    if (hi > kGasCap) {
        SILKRPC_WARN << "caller gas above allowance, capping: requested " << hi << ", cap " << kGasCap << "\n";
        hi = kGasCap;
    }
    auto cap = hi;

    SILKRPC_DEBUG << "hi: " << hi << ", lo: " << lo << ", cap: " << cap << "\n";

    silkworm::Transaction transaction{call.to_transaction()};
    while (lo + 1 < hi) {
        auto mid = (hi + lo) / 2;
        transaction.gas_limit = mid;

        auto failed = co_await try_execution(transaction);

        if (failed) {
            lo = mid;
        } else {
            hi = mid;
        }
    }

    if (hi == cap) {
        transaction.gas_limit = hi;
        auto failed = co_await try_execution(transaction);
        SILKRPC_DEBUG << "HI == cap tested again with " << (failed ? "failure" : "succeed") << "\n";

        if (failed) {
            throw EstimateGasException{-1, "gas required exceeds allowance (" + std::to_string(cap) + ")"};
        }
    }

    SILKRPC_DEBUG << "EstimateGasOracle::estimate_gas returns " << hi << "\n";
    co_return hi;
}

boost::asio::awaitable<bool> EstimateGasOracle::try_execution(const silkworm::Transaction& transaction) {
    const auto result = co_await executor_(transaction);

    bool failed = true;
    if (result.pre_check_error) {
        SILKRPC_DEBUG << "result error " << result.pre_check_error.value() << "\n";
    } else if (result.error_code == evmc_status_code::EVMC_SUCCESS) {
        SILKRPC_DEBUG << "result SUCCESS\n";
        failed = false;
    } else if (result.error_code == evmc_status_code::EVMC_INSUFFICIENT_BALANCE) {
        SILKRPC_DEBUG << "result INSUFFICIENTE BALANCE\n";
    } else {
        const auto error_message = EVMExecutor<>::get_error_message(result.error_code, result.data);
        SILKRPC_DEBUG << "result message " << error_message << ", code " << result.error_code << "\n";
        if (result.data.empty()) {
            throw EstimateGasException{-32000, error_message};
        } else {
            throw EstimateGasException{3, error_message, result.data};
        }
    }

    co_return failed;
}

} // namespace silkrpc::ego
