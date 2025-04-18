// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "estimate_gas_oracle.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/kv/grpc/client/remote_transaction.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_estimate_gas_oracle.hpp>

namespace silkworm::rpc {

class RemoteDatabaseTest : public db::test_util::KVTestBase {
  public:
    db::kv::api::CoherentStateCache state_cache;
};

using testing::_;
using testing::Return;

TEST_CASE("EstimateGasException") {
    SECTION("EstimateGasException(int64_t, std::string const&)") {
        static constexpr char kErrorMessage[] = "insufficient funds for transfer";
        constexpr int64_t kErrorCode = -1;
        EstimateGasException ex{kErrorCode, kErrorMessage};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
    SECTION("EstimateGasException(int64_t, std::string const&, silkworm::Bytes const&)") {
        static constexpr char kErrorMessage[] = "execution failed";
        constexpr int64_t kErrorCode = 3;
        const silkworm::Bytes data{*silkworm::from_hex("0x00")};
        EstimateGasException ex{kErrorCode, kErrorMessage, data};
        CHECK(ex.error_code() == kErrorCode);
        CHECK(ex.message() == kErrorMessage);
        CHECK(ex.data() == data);
        CHECK(std::strcmp(ex.what(), kErrorMessage) == 0);
    }
}

TEST_CASE("estimate gas") {
    WorkerPool pool{1};
    WorkerPool workers{1};

    intx::uint256 balance{1'000'000'000};
    silkworm::Account account{0, balance};

    AccountReader account_reader = [&account](const evmc::address& /*address*/, std::optional<TxnId> /* txn_id */) -> Task<std::optional<silkworm::Account>> {
        co_return account;
    };

    Call call;
    silkworm::Block block;
    block.header.gas_limit = kTxGas * 2;

    const silkworm::ChainConfig& config{kMainnetConfig};
    RemoteDatabaseTest remote_db_test;
    test::BackEndMock backend;
    db::chain::Providers providers = ethdb::kv::make_backend_providers(&backend);
    auto tx = std::make_unique<db::kv::grpc::client::RemoteTransaction>(remote_db_test.stub(),
                                                                        remote_db_test.grpc_context(),
                                                                        &remote_db_test.state_cache,
                                                                        providers);
    const db::chain::RemoteChainStorage storage{*tx, std::move(providers)};
    AccountsOverrides accounts_overrides;
    MockEstimateGasOracle estimate_gas_oracle{account_reader, config, workers, *tx, storage, accounts_overrides};

    SECTION("Call empty, always fails but success in first step") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0xa40e);
    }

    SECTION("Call empty, always succeeds") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(16).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();
        CHECK(estimate_gas == 0);
    }

    SECTION("Call empty, fails first call") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(1).WillOnce(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call empty, alternatively succeeds and fails") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(17)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillRepeatedly(Return(expect_result_fail));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x6d61);
    }

    SECTION("Call empty, alternatively succeeds and fails with intrinsic") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "intrinsic ",
            .pre_check_error_code = PreCheckErrorCode::kIntrinsicGasTooLow};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(16)
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check))
                .WillOnce(Return(expect_result_ok))
                .WillOnce(Return(expect_result_fail_pre_check));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call with gas, always fails but succes first and last step") {
        call.gas = kTxGas * 4;
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(17)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x1481e);
    }

    SECTION("Call with gas, always succeeds") {
        call.gas = kTxGas * 4;
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(17)
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0);
    }

    SECTION("Call with gas_price, gas not capped") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x4ce);
    }

    SECTION("Call with gas_price, gas capped") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{40'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x2717);
    }

    SECTION("Call with gas_price and value, gas not capped") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{10'000};
        call.value = intx::uint256{500'000'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x5205);
    }

    SECTION("Call with gas_price and value, gas capped") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
            .Times(16)
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_ok))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillOnce(Return(expect_result_fail))
            .WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0x30d2);
    }

    SECTION("Call gas above allowance, always succeeds, gas capped") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        call.gas = kGasCap * 2;
        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(26).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0);
    }

    SECTION("Call gas below minimum, always succeeds") {
        ExecutionResult expect_result_ok{.status_code = evmc_status_code::EVMC_SUCCESS};
        call.gas = kTxGas / 2;

        EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(16).WillRepeatedly(Return(expect_result_ok));
        auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
        const intx::uint256& estimate_gas = result.get();

        CHECK(estimate_gas == 0);
    }

    SECTION("Call with too high value, exception") {
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.value = intx::uint256{2'000'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _)).Times(1).WillRepeatedly(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail, try exception") {
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(1)
                .WillOnce(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail, try exception with data") {
        auto data = *silkworm::from_hex("2ac3c1d3e24b45c6c310534bc2dd84b5ed576335");
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_OUT_OF_GAS, .data = data};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(1)
                .WillOnce(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }

    SECTION("Call fail-EVMC_INVALID_INSTRUCTION, try exception") {
        ExecutionResult expect_result_fail_pre_check{
            .pre_check_error = "insufficient funds",
            .pre_check_error_code = PreCheckErrorCode::kInsufficientFunds};
        ExecutionResult expect_result_fail{.status_code = evmc_status_code::EVMC_INVALID_INSTRUCTION};
        call.gas = kTxGas * 2;
        call.gas_price = intx::uint256{20'000};
        call.value = intx::uint256{500'000'000};

        try {
            EXPECT_CALL(estimate_gas_oracle, try_execution(_, _))
                .Times(1)
                .WillOnce(Return(expect_result_fail));
            auto result = boost::asio::co_spawn(pool, estimate_gas_oracle.estimate_gas(call, block, 244087591818874), boost::asio::use_future);
            result.get();
            CHECK(false);
        } catch (const silkworm::rpc::EstimateGasException&) {
            CHECK(true);
        } catch (const std::exception&) {
            CHECK(false);
        } catch (...) {
            CHECK(false);
        }
    }
}
}  // namespace silkworm::rpc
