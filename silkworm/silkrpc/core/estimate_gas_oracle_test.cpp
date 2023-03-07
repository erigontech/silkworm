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
#include <cstring>
#include <iostream>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/endian/conversion.hpp>
#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/silkrpc/types/block.hpp>

namespace silkrpc::ego {

using Catch::Matchers::Message;

TEST_CASE("EstimateGasException") {
    SECTION("EstimateGasException(int64_t, std::string const&)") {
        const char* kErrorMessage{"insufficient funds for transfer"};
        const int64_t kErrorCode{-1};
        EstimateGasException ex{kErrorCode, kErrorMessage};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
    SECTION("EstimateGasException(int64_t, std::string const&, silkworm::Bytes const&)") {
        const char* kErrorMessage{"execution failed"};
        const int64_t kErrorCode{3};
        const silkworm::Bytes kData{*silkworm::from_hex("0x00")};
        EstimateGasException ex{kErrorCode, kErrorMessage, kData};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(ex.data() == kData);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
}

TEST_CASE("estimate gas") {
    boost::asio::thread_pool pool{1};

    uint64_t count{0};
    std::vector<bool> steps;
    intx::uint256 kBalance{1'000'000'000};

    silkrpc::ExecutionResult kSuccessResult{evmc_status_code::EVMC_SUCCESS};
    silkrpc::ExecutionResult kFailureResult{evmc_status_code::EVMC_INSUFFICIENT_BALANCE};

    silkworm::BlockHeader kBlockHeader;
    kBlockHeader.gas_limit = kTxGas * 2;

    silkworm::Account kAccount{0, kBalance};

    Executor executor = [&steps, &count](const silkworm::Transaction& transaction) -> boost::asio::awaitable<silkrpc::ExecutionResult> {
        bool success = steps[count++];
        silkrpc::ExecutionResult result{success ? evmc_status_code::EVMC_SUCCESS : evmc_status_code::EVMC_INSUFFICIENT_BALANCE};
        co_return result;
    };

    BlockHeaderProvider block_header_provider = [&kBlockHeader](uint64_t block_number) -> boost::asio::awaitable<silkworm::BlockHeader> {
        co_return kBlockHeader;
    };

    AccountReader account_reader = [&kAccount](const evmc::address& address, uint64_t block_number) -> boost::asio::awaitable<std::optional<silkworm::Account>> {
        co_return kAccount;
    };

    Call call;
    EstimateGasOracle estimate_gas_oracle{block_header_provider, account_reader, executor};

    SECTION("Call empty, always fails but last step") {
        steps.resize(16);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[15] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call empty, always succeeds") {
        steps.resize(16);
        std::fill_n(steps.begin(), steps.size(), true);

        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call empty, alternatively fails and succeeds") {
        int current = false;
        auto generate = [&current]() -> bool {
            return ++current % 2 == 0;;
        };
        steps.resize(16);
        std::generate_n(steps.begin(), steps.size(), generate);

        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == 0x88b6);
    }

    SECTION("Call empty, alternatively succeeds and fails") {
        int current = false;
        auto generate = [&current]() -> bool {
            return current++ % 2 == 0;;
        };
        steps.resize(16);
        std::generate_n(steps.begin(), steps.size(), generate);

        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == 0x6d5e);
    }

    SECTION("Call with gas, always fails but last step") {
        call.gas = kTxGas * 4;
        steps.resize(17);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[16] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 4);
    }

    SECTION("Call with gas, always succeeds") {
        call.gas = kTxGas * 4;
        steps.resize(17);
        std::fill_n(steps.begin(), steps.size(), true);
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call with gas_price, gas not capped") {
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};
        steps.resize(16);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[15] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call with gas_price, gas capped") {
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{40'000};
        steps.resize(13);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[12] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == 0x61a8);
    }

    SECTION("Call with gas_price and value, gas not capped") {
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};
        call.value = intx::uint256{500'000'000};
        steps.resize(16);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[15] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas * 2);
    }

    SECTION("Call with gas_price and value, gas capped") {
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};
        steps.resize(13);
        std::fill_n(steps.begin(), steps.size(), false);
        steps[12] = true;
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == 0x61a8);
    }

    SECTION("Call gas above allowance, always succeeds, gas capped") {
        call.gas = kGasCap * 2;
        steps.resize(26);
        std::fill_n(steps.begin(), steps.size(), true);
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call gas below minimum, always succeeds") {
        call.gas = kTxGas / 2;

        steps.resize(26);
        std::fill_n(steps.begin(), steps.size(), true);
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
        const intx::uint256 &estimate_gas = result.get();

        CHECK(estimate_gas == kTxGas);
    }

    SECTION("Call with too high value, exception") {
        call.value = intx::uint256{2'000'000'000};
        steps.resize(16);
        std::fill_n(steps.begin(), steps.size(), false);

        try {
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, 0), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const std::exception&) {
            CHECK(true);
        }
    }
}

} // namespace silkrpc::ego
