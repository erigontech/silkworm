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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/test_util/context_test_base.hpp>
#include <silkworm/rpc/test_util/mock_chain_storage.hpp>
#include <silkworm/rpc/test_util/mock_transaction.hpp>

namespace silkworm::rpc::state {

using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Unused;

struct RemoteStateTest : public test::ContextTestBase {
    test::MockTransaction transaction;
    boost::asio::any_io_executor current_executor{io_context_.get_executor()};
    test::MockChainStorage chain_storage;
};

TEST_CASE_METHOD(RemoteStateTest, "async remote buffer", "[rpc][core][remote_buffer]") {
    SECTION("read_code for empty hash") {
        EXPECT_CALL(transaction, get_one(db::table::kCodeName, _))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto code_read{spawn_and_wait(state.read_code(silkworm::kEmptyHash))};
        CHECK(code_read.empty());
    }

    SECTION("read_code for non-empty hash") {
        static const silkworm::Bytes code{*silkworm::from_hex("0x0608")};
        EXPECT_CALL(transaction, get_one(db::table::kCodeName, _))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return code;
            }));
        const BlockNum block_number = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const auto code_read{spawn_and_wait(state.read_code(code_hash))};
        CHECK(code_read == silkworm::ByteView{code});
    }

    SECTION("read_code with empty response from db") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        EXPECT_CALL(transaction, get_one(db::table::kCodeName, _))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState state(current_executor, transaction, chain_storage, block_number);
        const auto code_read = state.read_code(code_hash);
        CHECK(code_read.empty());
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("read_storage with empty response from db") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        EXPECT_CALL(transaction, get(db::table::kStorageHistoryName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{Bytes{}, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kPlainStateName, _, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        const auto storage_read = remote_state.read_storage(address, 0, location);
        CHECK(storage_read == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("read_account with empty response from db") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{Bytes{}, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        const auto account_read = remote_state.read_account(address);
        CHECK(account_read == std::nullopt);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("read_header with empty response from chain storage") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        EXPECT_CALL(chain_storage, read_header(block_number, block_hash))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        const auto header_read = remote_state.read_header(block_number, block_hash);
        CHECK(header_read == std::nullopt);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("read_body with empty response from from chain storage") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        silkworm::BlockBody body;
        EXPECT_CALL(chain_storage, read_body(block_hash, block_number, body))
            .WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        const auto success = remote_state.read_body(block_number, block_hash, body);
        CHECK(success);
        CHECK(body == silkworm::BlockBody{});
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("total_difficulty with empty response from db") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        EXPECT_CALL(chain_storage, read_total_difficulty(block_hash, block_number))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<intx::uint256>> { co_return std::nullopt; }));
        const auto total_difficulty = remote_state.total_difficulty(block_number, block_hash);
        CHECK(total_difficulty == std::nullopt);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("previous_incarnation returns ok") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        const evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        const auto prev_incarnation = remote_state.previous_incarnation(address);
        CHECK(prev_incarnation == 0);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("current_canonical_block throws not implemented") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        CHECK_THROWS_AS(remote_state.current_canonical_block(), std::logic_error);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("canonical_hash throws not implemented") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        CHECK_THROWS_AS(remote_state.canonical_hash(block_number), std::logic_error);
        io_context_.stop();
        io_context_thread.join();
    }

    SECTION("state_root_hash throws not implemented") {
        std::thread io_context_thread{[&]() { io_context_.run(); }};
        const BlockNum block_number = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_number);
        CHECK_THROWS_AS(remote_state.state_root_hash(), std::logic_error);
        io_context_.stop();
        io_context_thread.join();
    }

    /*
        SECTION("read_code with exception") {
            boost::asio::io_context io_context;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
            std::thread io_context_thread{[&io_context]() { io_context.run(); }};

            silkworm::Bytes code{*silkworm::from_hex("0x0608")};
            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_number = 1'000'000;
            const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(io_context, transaction, storage, block_number);
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
            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_number = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(io_context, transaction, storage, block_number);
            auto ret_storage = remote_state.read_storage(address, 0, location);
            CHECK(ret_storage == evmc::bytes32{});
            io_context.stop();
            io_context_thread.join();
        }

        SECTION("read_account with exception") {
            boost::asio::io_context io_context;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{io_context.get_executor()};
            std::thread io_context_thread{[&io_context]() { io_context.run(); }};

            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_number = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(io_context, transaction, storage, block_number);
            auto account = remote_state.read_account(address);
            CHECK(account == std::nullopt);
            io_context.stop();
            io_context_thread.join();
        }
    */

    SECTION("AsyncRemoteState::read_account for empty response from db") {
        EXPECT_CALL(transaction, get(db::table::kAccountHistoryName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{Bytes{}, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_one(db::table::kPlainStateName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        const auto account_read{spawn_and_wait(state.read_account(address))};
        CHECK(account_read == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_code with empty response from db") {
        EXPECT_CALL(transaction, get_one(db::table::kCodeName, _))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        const auto code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto code_read{spawn_and_wait(state.read_code(code_hash))};
        CHECK(code_read.empty());
    }

    SECTION("AsyncRemoteState::read_storage with empty response from db") {
        EXPECT_CALL(transaction, get(db::table::kStorageHistoryName, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{Bytes{}, Bytes{}};
            }));
        EXPECT_CALL(transaction, get_both_range(db::table::kPlainStateName, _, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<Bytes>> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        const auto location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto storage_read{spawn_and_wait(state.read_storage(address, 0, location))};
        CHECK(storage_read == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
    }

    SECTION("AsyncRemoteState::previous_incarnation returns ok") {
        const BlockNum block_number = 1'000'000;
        const evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto prev_incarnation{spawn_and_wait(state.previous_incarnation(address))};
        CHECK(prev_incarnation == 0);
    }

    SECTION("AsyncRemoteState::state_root_hash returns ok") {
        const BlockNum block_number = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto state_root_hash{spawn_and_wait(state.state_root_hash())};
        CHECK(state_root_hash == evmc::bytes32{});
    }

    SECTION("AsyncRemoteState::current_canonical_block returns ok") {
        const BlockNum block_number = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto current_canonical_block{spawn_and_wait(state.current_canonical_block())};
        CHECK(current_canonical_block == 0);
    }

    SECTION("AsyncRemoteState::total_difficulty with empty response from chain storage") {
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        EXPECT_CALL(chain_storage, read_total_difficulty(block_hash, block_number))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<intx::uint256>> { co_return std::nullopt; }));
        const auto total_difficulty{spawn_and_wait(state.total_difficulty(block_number, block_hash))};
        CHECK(total_difficulty == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_header with empty response from chain storage") {
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        EXPECT_CALL(chain_storage, read_header(block_number, block_hash))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        const auto block_header{spawn_and_wait(state.read_header(block_number, block_hash))};
        CHECK(block_header == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_body with empty response from from chain storage") {
        const BlockNum block_number = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        AsyncRemoteState state{transaction, chain_storage, block_number};
        silkworm::BlockBody body;
        EXPECT_CALL(chain_storage, read_body(block_hash, block_number, body))
            .WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        const auto success{spawn_and_wait(state.read_body(block_number, block_hash, body))};
        CHECK(success);
        CHECK(body == silkworm::BlockBody{});
    }

    SECTION("AsyncRemoteState::canonical_hash for empty response from chain storage") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, _))
            .WillRepeatedly(InvokeWithoutArgs([=]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const BlockNum block_number = 1'000'000;
        EXPECT_CALL(chain_storage, read_canonical_hash(block_number))
            .WillOnce(Invoke([](Unused) -> Task<std::optional<Hash>> { co_return std::nullopt; }));
        AsyncRemoteState state{transaction, chain_storage, block_number};
        const auto canonical_hash{spawn_and_wait(state.canonical_hash(block_number))};
        CHECK(canonical_hash == std::nullopt);
    }
}

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteStateTest, "RemoteState") {
    RemoteState remote_state(current_executor, transaction, chain_storage, 0);

    SECTION("overridden write methods do nothing") {
        CHECK_NOTHROW(remote_state.insert_block(silkworm::Block{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.canonize_block(0, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.decanonize_block(0));
        CHECK_NOTHROW(remote_state.insert_receipts(0, std::vector<silkworm::Receipt>{}));
        CHECK_NOTHROW(remote_state.begin_block(0, 0));
        CHECK_NOTHROW(remote_state.update_account(evmc::address{}, std::nullopt, std::nullopt));
        CHECK_NOTHROW(remote_state.update_account_code(evmc::address{}, 0, evmc::bytes32{}, silkworm::ByteView{}));
        CHECK_NOTHROW(remote_state.update_storage(evmc::address{}, 0, evmc::bytes32{}, evmc::bytes32{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.unwind_state_changes(0));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::state
