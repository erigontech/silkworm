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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/execution/remote_state.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

using db::chain::RemoteChainStorage;

struct EVMExecutorTest : public test_util::ServiceContextTestBase {
    EVMExecutorTest() {
        pool.start();
    }

    db::test_util::MockTransaction transaction;
    WorkerPool workers{1};
    ClientContextPool pool{1};
    boost::asio::any_io_executor io_executor{pool.next_ioc().get_executor()};
    test::BackEndMock backend;
    RemoteChainStorage storage{transaction, ethdb::kv::make_backend_providers(&backend)};
    const uint64_t chain_id{11155111};
    const ChainConfig* chain_config_ptr{lookup_chain_config(chain_id)};
    BlockNum block_num{6'000'000};
    std::shared_ptr<State> state{std::make_shared<execution::RemoteState>(io_executor, transaction, storage, block_num)};
};

#ifndef SILKWORM_SANITIZE
using testing::_;
using testing::Invoke;
using testing::Unused;

TEST_CASE_METHOD(EVMExecutorTest, "EVMExecutor") {
    SECTION("failed if gas_limit < intrinsic_gas") {
        silkworm::Transaction txn{};
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        silkworm::Block block{};
        block.header.number = block_num;

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {});
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "intrinsic gas too low: have 0, want 53000");
    }

    SECTION("failed if base_fee_per_gas > max_fee_per_gas ") {
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x7;
        block.header.number = block_num;
        silkworm::Transaction txn{};
        txn.gas_limit = 100'000;
        txn.max_fee_per_gas = 0x2;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {});
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "fee cap less than block base fee: address 0xa872626373628737383927236382161739290870, gasFeeCap: 2 baseFee: 7");
    }

    SECTION("failed if  max_priority_fee_per_gas > max_fee_per_gas ") {
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_num;
        silkworm::Transaction txn{};
        txn.gas_limit = 100'000;
        txn.max_fee_per_gas = 0x2;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        txn.max_priority_fee_per_gas = 0x18;

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {});
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "tip higher than fee cap: address 0xa872626373628737383927236382161739290870, tip: 24 gasFeeCap: 2");
    }

    SECTION("failed if transaction cost greater user amount") {
        auto cursor = std::make_shared<silkworm::db::test_util::MockCursor>();
        EXPECT_CALL(transaction, get_as_of(_)).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));

        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_num;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.gas_limit = 60000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {});
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "insufficient funds for gas * price + value: address 0xa872626373628737383927236382161739290870 have 0 want 60000");
    }

    SECTION("doesn't fail if transaction cost greater user amount && gasBailout == true") {
        auto cursor = std::make_shared<silkworm::db::test_util::MockCursor>();
        EXPECT_CALL(transaction, get_as_of(_)).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));

        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_num;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.gas_limit = 60000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {}, false, /* gasBailout */ true);
        executor.reset();
        CHECK(result.error_code == 0);
    }

    AccessList access_list{
        {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
         {
             0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
             0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
         }},
        {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
    };

    SECTION("call returns SUCCESS") {
        auto cursor = std::make_shared<silkworm::db::test_util::MockCursor>();
        EXPECT_CALL(transaction, get_as_of(_)).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));

        silkworm::Block block{};
        block.header.number = block_num;
        silkworm::Transaction txn{};
        txn.gas_limit = 600000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        txn.access_list = access_list;

        EVMExecutor executor{block, *chain_config_ptr, workers, state};
        const auto result = executor.call(block, txn, {}, true, /* gasBailout */ true);
        CHECK(result.error_code == 0);
    }

    static silkworm::Bytes error_data{
        0x08, 0xc3, 0x79, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4f, 0x77, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x3a, 0x20, 0x63,
        0x61, 0x6c, 0x6c, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x77, 0x6e, 0x65, 0x72};

    static silkworm::Bytes short_error_data_1{0x08, 0xc3};

    static silkworm::Bytes short_error_data_2{
        0x08, 0xc3, 0x79, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    static silkworm::Bytes short_error_data_3{
        0x08, 0xc3, 0x79, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00};

    static silkworm::Bytes short_error_data_4{
        0x08, 0xc3, 0x79, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x4f, 0x77, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x3a,
        0x20, 0x63, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x20, 0x69, 0x73, 0x20};

    SECTION("get_error_message(EVMC_FAILURE) with short error_data_1") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, short_error_data_1);
        CHECK(error_message == "execution failed");  // only short answer because error_data is too short */
    }

    SECTION("get_error_message(EVMC_FAILURE) with short error_data_2") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, short_error_data_2);
        CHECK(error_message == "execution failed");  // only short answer because error_data is too short */
    }

    SECTION("get_error_message(EVMC_FAILURE) with short error_data_3") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, short_error_data_3);
        CHECK(error_message == "execution failed");  // only short answer because error_data is too short */
    }

    SECTION("get_error_message(EVMC_FAILURE) with short error_data_4") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, short_error_data_4);
        CHECK(error_message == "execution failed");  // only short answer because error_data is too short */
    }

    SECTION("get_error_message(EVMC_FAILURE) with full error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, error_data);
        CHECK(error_message == "execution failed: Ownable: caller is not the owner");
    }

    SECTION("get_error_message(EVMC_FAILURE) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_FAILURE, error_data, false);
        CHECK(error_message == "execution failed");
    }

    SECTION("get_error_message(EVMC_REVERT) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_REVERT, error_data, false);
        CHECK(error_message == "execution reverted");
    }

    SECTION("get_error_message(EVMC_OUT_OF_GAS) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_OUT_OF_GAS, error_data, false);
        CHECK(error_message == "out of gas");
    }

    SECTION("get_error_message(EVMC_INVALID_INSTRUCTION) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_INVALID_INSTRUCTION, error_data, false);
        CHECK(error_message == "invalid instruction");
    }

    SECTION("get_error_message(EVMC_UNDEFINED_INSTRUCTION) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_UNDEFINED_INSTRUCTION, error_data, false);
        CHECK(error_message == "invalid opcode");
    }

    SECTION("get_error_message(EVMC_STACK_OVERFLOW) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_STACK_OVERFLOW, error_data, false);
        CHECK(error_message == "stack overflow");
    }

    SECTION("get_error_message(EVMC_STACK_UNDERFLOW) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_STACK_UNDERFLOW, error_data, false);
        CHECK(error_message == "stack underflow");
    }

    SECTION("get_error_message(EVMC_BAD_JUMP_DESTINATION) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_BAD_JUMP_DESTINATION, error_data, false);
        CHECK(error_message == "invalid jump destination");
    }

    SECTION("get_error_message(EVMC_INVALID_MEMORY_ACCESS) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_INVALID_MEMORY_ACCESS, error_data, false);
        CHECK(error_message == "invalid memory access");
    }

    SECTION("get_error_message(EVMC_CALL_DEPTH_EXCEEDED) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_CALL_DEPTH_EXCEEDED, error_data, false);
        CHECK(error_message == "call depth exceeded");
    }

    SECTION("get_error_message(EVMC_STATIC_MODE_VIOLATION) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_STATIC_MODE_VIOLATION, error_data, false);
        CHECK(error_message == "static mode violation");
    }

    SECTION("get_error_message(EVMC_PRECOMPILE_FAILURE) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_PRECOMPILE_FAILURE, error_data, false);
        CHECK(error_message == "precompile failure");
    }

    SECTION("get_error_message(EVMC_CONTRACT_VALIDATION_FAILURE) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE, error_data, false);
        CHECK(error_message == "contract validation failure");
    }

    SECTION("get_error_message(EVMC_ARGUMENT_OUT_OF_RANGE) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_ARGUMENT_OUT_OF_RANGE, error_data, false);
        CHECK(error_message == "argument out of range");
    }

    SECTION("get_error_message(wrong status_code) with short error") {
        const auto error_message = EVMExecutor::get_error_message(8888, error_data, false);
        CHECK(error_message == "unknown error code");
    }

    SECTION("get_error_message(EVMC_WASM_UNREACHABLE_INSTRUCTION) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_WASM_UNREACHABLE_INSTRUCTION, error_data, false);
        CHECK(error_message == "wasm unreachable instruction");
    }

    SECTION("get_error_message(EVMC_WASM_TRAP) with short error") {
        const auto error_message = EVMExecutor::get_error_message(evmc_status_code::EVMC_WASM_TRAP, error_data, false);
        CHECK(error_message == "wasm trap");
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc
