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

#include "remote_state.hpp"

#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/storage/remote_chain_storage.hpp>
#include <silkworm/rpc/test/context_test_base.hpp>
#include <silkworm/rpc/test/mock_back_end.hpp>
#include <silkworm/rpc/test/mock_chain_storage.hpp>
#include <silkworm/rpc/test/mock_database_reader.hpp>

namespace silkworm::rpc::state {

using Catch::Matchers::Message;
using evmc::literals::operator""_bytes32;
using evmc::literals::operator""_address;
using Catch::Matchers::Message;
using testing::_;
using testing::DoAll;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::Unused;

TEST_CASE("async remote buffer", "[rpc][core][remote_buffer]") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    const auto backend = std::make_unique<test::BackEndMock>();

    class MockDatabaseReader : public core::rawdb::DatabaseReader {
      public:
        MockDatabaseReader() = default;
        explicit MockDatabaseReader(silkworm::Bytes value) : value_(std::move(value)) {}

        [[nodiscard]] Task<KeyValue> get(const std::string& /*table*/, silkworm::ByteView /*key*/) const override {
            co_return KeyValue{};
        }
        [[nodiscard]] Task<silkworm::Bytes> get_one(const std::string& /*table*/, silkworm::ByteView /*key*/) const override {
            co_return value_;
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

      private:
        silkworm::Bytes value_;
    };

    SECTION("read_code for empty hash") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        auto future_code{boost::asio::co_spawn(io_context, state.read_code(silkworm::kEmptyHash), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get().empty());
    }

    SECTION("read_code for non-empty hash") {
        boost::asio::io_context io_context;
        silkworm::Bytes code{*silkworm::from_hex("0x0608")};
        MockDatabaseReader db_reader{code};
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        auto future_code{boost::asio::co_spawn(io_context, state.read_code(code_hash), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == silkworm::ByteView{code});
    }

    SECTION("read_code with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        silkworm::Bytes code{*silkworm::from_hex("0x0608")};
        MockDatabaseReader db_reader{code};
        const BlockNum block_number = 1'000'000;
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        auto ret_code = remote_state.read_code(code_hash);
        CHECK(ret_code == code);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("read_storage with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        silkworm::Bytes storage{*silkworm::from_hex("0x0608")};
        MockDatabaseReader db_reader{storage};
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage chain_storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, chain_storage, block_number);
        auto ret_storage = remote_state.read_storage(address, 0, location);
        CHECK(ret_storage == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("read_account with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        auto account = remote_state.read_account(address);
        CHECK(account == std::nullopt);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("read_header with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        rpc::test::MockChainStorage chain_storage;
        RemoteState remote_state(current_executor, db_reader, chain_storage, block_number);
        silkworm::Hash hash{block_hash};
        EXPECT_CALL(chain_storage, read_header(block_number, hash)).WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        auto header = remote_state.read_header(block_number, block_hash);
        CHECK(header == std::nullopt);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("read_body with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        silkworm::BlockBody body;
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        rpc::test::MockChainStorage chain_storage;
        RemoteState remote_state(current_executor, db_reader, chain_storage, block_number);
        silkworm::Hash hash{block_hash};
        EXPECT_CALL(chain_storage, read_body(hash, block_number, body)).WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        auto valid = remote_state.read_body(block_number, block_hash, body);
        CHECK(valid == true);
        CHECK(body == silkworm::BlockBody{});
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("total_difficulty with empty response from db") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        rpc::test::MockChainStorage chain_storage;
        silkworm::Hash hash{block_hash};
        RemoteState remote_state(current_executor, db_reader, chain_storage, block_number);
        EXPECT_CALL(chain_storage, read_total_difficulty(hash, block_number)).WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<intx::uint256>> { co_return std::nullopt; }));
        auto total_difficulty = remote_state.total_difficulty(block_number, block_hash);
        CHECK(total_difficulty == std::nullopt);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("previous_incarnation returns ok") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        auto prev_incarnation = remote_state.previous_incarnation(address);
        CHECK(prev_incarnation == 0);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("current_canonical_block returns ok") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        CHECK_THROWS_AS(remote_state.current_canonical_block(), std::logic_error);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("canonical_hash with returns ok") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        CHECK_THROWS_AS(remote_state.canonical_hash(block_number), std::logic_error);
        io_context.stop();
        io_context_thread.join();
    }

    SECTION("state_root_hash with returns ok") {
        boost::asio::io_context io_context;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
        std::thread io_context_thread{[&io_context]() { io_context.run(); }};

        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        boost::asio::any_io_executor current_executor = io_context.get_executor();
        const RemoteChainStorage storage{db_reader, backend.get()};
        RemoteState remote_state(current_executor, db_reader, storage, block_number);
        CHECK_THROWS_AS(remote_state.state_root_hash(), std::logic_error);
        io_context.stop();
        io_context_thread.join();
    }

    /*
        SECTION("read_code with exception") {
            boost::asio::io_context io_context;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
            std::thread io_context_thread{[&io_context]() { io_context.run(); }};

            silkworm::Bytes code{*silkworm::from_hex("0x0608")};
            MockDatabaseFailingReader db_reader{code};
            const BlockNum block_number = 1'000'000;
            const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{db_reader, backend.get()};
            RemoteState remote_state(io_context, db_reader, storage, block_number);
            auto ret_code = remote_state.read_code(code_hash);
            CHECK(ret_code == silkworm::ByteView{});
            io_context.stop();
            io_context_thread.join();
        }

        SECTION("read_storage with exception") {
            boost::asio::io_context io_context;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
            std::thread io_context_thread{[&io_context]() { io_context.run(); }};

            silkworm::Bytes storage{*silkworm::from_hex("0x0608")};
            MockDatabaseFailingReader db_reader{storage};
            const BlockNum block_number = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{db_reader, backend.get()};
            RemoteState remote_state(io_context, db_reader, storage, block_number);
            auto ret_storage = remote_state.read_storage(address, 0, location);
            CHECK(ret_storage == evmc::bytes32{});
            io_context.stop();
            io_context_thread.join();
        }

        SECTION("read_account with exception") {
            boost::asio::io_context io_context;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
            std::thread io_context_thread{[&io_context]() { io_context.run(); }};

            MockDatabaseFailingReader db_reader;
            const BlockNum block_number = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const RemoteChainStorage storage{db_reader, backend.get()};
            RemoteState remote_state(io_context, db_reader, storage, block_number);
            auto account = remote_state.read_account(address);
            CHECK(account == std::nullopt);
            io_context.stop();
            io_context_thread.join();
        }
    */

    SECTION("AsyncRemoteState::read_account for empty response from db") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        auto future_code{boost::asio::co_spawn(io_context, state.read_account(address), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_code with empty response from db") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        auto future_code{boost::asio::co_spawn(io_context, state.read_code(code_hash), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get().empty());
    }

    SECTION("AsyncRemoteState::read_storage with empty response from db") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        auto future_code{boost::asio::co_spawn(io_context, state.read_storage(address, 0, location), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == evmc::bytes32{});
    }

    SECTION("AsyncRemoteState::previous_incarnation returns ok") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        auto future_code{boost::asio::co_spawn(io_context, state.previous_incarnation(address), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == 0);
    }

    SECTION("AsyncRemoteState::state_root_hash returns ok") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        auto future_code{boost::asio::co_spawn(io_context, state.state_root_hash(), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == evmc::bytes32{});
    }

    SECTION("AsyncRemoteState::current_canonical_block returns ok") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        auto future_code{boost::asio::co_spawn(io_context, state.current_canonical_block(), boost::asio::use_future)};
        io_context.run();
        CHECK(future_code.get() == 0);
    }

    SECTION("AsyncRemoteState::total_difficulty returns exceptions") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        auto future_code{boost::asio::co_spawn(io_context, state.total_difficulty(block_number, block_hash), boost::asio::use_future)};
        io_context.run();
        CHECK_THROWS_AS(future_code.get(), std::exception);
    }

    SECTION("AsyncRemoteState::read_header") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        rpc::test::MockChainStorage chain_storage;
        silkworm::Hash hash{block_hash};
        AsyncRemoteState state{db_reader, chain_storage, block_number};
        EXPECT_CALL(chain_storage, read_header(block_number, hash)).WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        auto future_code{boost::asio::co_spawn(io_context, state.read_header(block_number, block_hash), boost::asio::use_future)};
        io_context.run();
    }

    SECTION("AsyncRemoteState::read_body") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const auto block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        rpc::test::MockChainStorage chain_storage;
        silkworm::Hash hash{block_hash};
        AsyncRemoteState state{db_reader, chain_storage, block_number};
        silkworm::BlockBody body;
        EXPECT_CALL(chain_storage, read_body(hash, block_number, body)).WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        auto future_code{boost::asio::co_spawn(io_context, state.read_body(block_number, block_hash, body), boost::asio::use_future)};
        io_context.run();
    }

    SECTION("AsyncRemoteState::canonical_hash returns exceptions") {
        boost::asio::io_context io_context;
        MockDatabaseReader db_reader;
        const BlockNum block_number = 1'000'000;
        const RemoteChainStorage storage{db_reader, backend.get()};
        AsyncRemoteState state{db_reader, storage, block_number};
        auto future_code{boost::asio::co_spawn(io_context, state.canonical_hash(block_number), boost::asio::use_future)};
        io_context.run();
        CHECK_THROWS_AS(future_code.get(), std::exception);
    }
}

struct RemoteStateTest : public test::ContextTestBase {
    test::MockDatabaseReader database_reader_;
    boost::asio::io_context io_context;
    boost::asio::any_io_executor current_executor{io_context.get_executor()};
    std::unique_ptr<test::BackEndMock> backend{std::make_unique<test::BackEndMock>()};
    RemoteChainStorage storage{database_reader_, backend.get()};
    RemoteState remote_state_{current_executor, database_reader_, storage, 0};
};

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteStateTest, "RemoteState") {
    silkworm::test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    SECTION("overridden write methods do nothing") {
        CHECK_NOTHROW(remote_state_.insert_block(silkworm::Block{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state_.canonize_block(0, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state_.decanonize_block(0));
        CHECK_NOTHROW(remote_state_.insert_receipts(0, std::vector<silkworm::Receipt>{}));
        CHECK_NOTHROW(remote_state_.begin_block(0));
        CHECK_NOTHROW(remote_state_.update_account(evmc::address{}, std::nullopt, std::nullopt));
        CHECK_NOTHROW(remote_state_.update_account_code(evmc::address{}, 0, evmc::bytes32{}, silkworm::ByteView{}));
        CHECK_NOTHROW(remote_state_.update_storage(evmc::address{}, 0, evmc::bytes32{}, evmc::bytes32{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state_.unwind_state_changes(0));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::state
