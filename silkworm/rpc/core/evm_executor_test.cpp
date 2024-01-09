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
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/storage/remote_chain_storage.hpp>
#include <silkworm/rpc/test/dummy_transaction.hpp>
#include <silkworm/rpc/test/mock_back_end.hpp>
#include <silkworm/rpc/test/mock_cursor.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc {

#ifndef SILKWORM_SANITIZE
TEST_CASE("EVMExecutor") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    class StubDatabase : public core::rawdb::DatabaseReader {
        [[nodiscard]] Task<KeyValue> get(const std::string& /*table*/, silkworm::ByteView /*key*/) const override {
            co_return KeyValue{};
        }
        [[nodiscard]] Task<silkworm::Bytes> get_one(const std::string& /*table*/, silkworm::ByteView /*key*/) const override {
            co_return silkworm::Bytes{};
        }
        [[nodiscard]] Task<std::optional<silkworm::Bytes>> get_both_range(const std::string& /*table*/, silkworm::ByteView /*key*/, silkworm::ByteView /*subkey*/) const override {
            co_return silkworm::Bytes{};
        }
        [[nodiscard]] Task<void> walk(const std::string& /*table*/, silkworm::ByteView /*start_key*/, uint32_t /*fixed_bits*/, core::rawdb::Walker /*w*/) const override {
            co_return;
        }
        [[nodiscard]] Task<void> for_prefix(const std::string& /*table*/, silkworm::ByteView /*prefix*/, core::rawdb::Walker /*w*/) const override {
            co_return;
        }
    };

    SECTION("failed if gas_limit < intrinsic_gas") {
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 10000;
        silkworm::Transaction txn{};
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        silkworm::Block block{};
        block.header.number = block_number;

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};

        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {});
        my_pool.stop();
        my_pool.join();
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "intrinsic gas too low: address 0xa872626373628737383927236382161739290870, have 0, want 53000");
    }

    SECTION("failed if base_fee_per_gas > max_fee_per_gas ") {
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 6000000;
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x7;
        block.header.number = block_number;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};
        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {});
        my_pool.stop();
        my_pool.join();
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "fee cap less than block base fee: address 0xa872626373628737383927236382161739290870, gasFeeCap: 2 baseFee: 7");
    }

    SECTION("failed if  max_priority_fee_per_gas > max_fee_per_gas ") {
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 6000000;
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_number;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        txn.max_priority_fee_per_gas = 0x18;

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};
        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {});
        my_pool.stop();
        my_pool.join();
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "tip higher than fee cap: address 0xa872626373628737383927236382161739290870, tip: 24 gasFeeCap: 2");
    }

    SECTION("failed if transaction cost greater user amount") {
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 6000000;
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_number;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.gas_limit = 60000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};
        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {});
        my_pool.stop();
        my_pool.join();
        CHECK(result.error_code == std::nullopt);
        CHECK(result.pre_check_error.value() == "insufficient funds for gas * price + value: address 0xa872626373628737383927236382161739290870, have 0, want 60000");
    }

    SECTION("doesn't fail if transaction cost greater user amount && gasBailout == true") {
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 6000000;
        silkworm::Block block{};
        block.header.base_fee_per_gas = 0x1;
        block.header.number = block_number;
        silkworm::Transaction txn{};
        txn.max_fee_per_gas = 0x2;
        txn.gas_limit = 60000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};
        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {}, false, /* gasBailout */ true);
        executor.reset();
        my_pool.stop();
        my_pool.join();
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
        StubDatabase tx_database;
        const uint64_t chain_id = 5;
        const auto chain_config_ptr = lookup_chain_config(chain_id);

        ClientContextPool my_pool{1};
        boost::asio::thread_pool workers{1};
        my_pool.start();

        const auto block_number = 6000000;
        silkworm::Block block{};
        block.header.number = block_number;
        silkworm::Transaction txn{};
        txn.gas_limit = 600000;
        txn.set_sender(0xa872626373628737383927236382161739290870_address);
        txn.access_list = access_list;

        boost::asio::any_io_executor current_executor = my_pool.next_io_context().get_executor();
        std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
        test::DummyTransaction tx{0, mock_cursor};
        const auto backend = std::make_unique<test::BackEndMock>();
        const RemoteChainStorage storage{tx_database, backend.get()};
        auto state = tx.create_state(current_executor, tx_database, storage, block_number);
        EVMExecutor executor{*chain_config_ptr, workers, state};
        auto result = executor.call(block, txn, {}, true, /* gasBailout */ true);
        my_pool.stop();
        my_pool.join();
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
