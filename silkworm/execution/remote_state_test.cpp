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
#include <silkworm/db/test_util/mock_chain_storage.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>

namespace silkworm::execution {

using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Unused;

struct RemoteStateTest : public silkworm::test_util::ContextTestBase {
    db::test_util::MockTransaction transaction;
    boost::asio::any_io_executor current_executor{ioc_.get_executor()};
    db::test_util::MockChainStorage chain_storage;
};

TEST_CASE_METHOD(RemoteStateTest, "async remote buffer", "[rpc][core][remote_buffer]") {
    auto cursor = std::make_shared<silkworm::db::test_util::MockCursor>();
    const evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};

    SECTION("read_code for empty hash") {
        EXPECT_CALL(transaction, get_one(db::table::kCodeName, _))
            .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto code_read{spawn_and_wait(state.read_code(address, kEmptyHash))};
        CHECK(code_read.empty());
    }

    SECTION("read_code for non-empty hash") {
        static const Bytes kCode{*from_hex("0x0608")};

        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = kCode};
            co_return response;
        }));

        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const evmc::bytes32 code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const auto code_read{spawn_and_wait(state.read_code(address, code_hash))};
        CHECK(code_read == ByteView{kCode});
    }

    SECTION("read_code with empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        const evmc::bytes32 code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState state(current_executor, transaction, chain_storage, block_num);
        const auto code_read = state.read_code(address, code_hash);
        CHECK(code_read.empty());
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("read_storage with empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        const evmc::bytes32 location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        const auto storage_read = remote_state.read_storage(address, 0, location);
        CHECK(storage_read == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("read_account with empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        const auto account_read = remote_state.read_account(address);
        CHECK(account_read == std::nullopt);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("read_header with empty response from chain storage") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        EXPECT_CALL(chain_storage, read_header(block_num, block_hash))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        const auto header_read = remote_state.read_header(block_num, block_hash);
        CHECK(header_read == std::nullopt);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("read_body with empty response from from chain storage") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        BlockBody body;
        EXPECT_CALL(chain_storage, read_body(block_hash, block_num, body))
            .WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        const auto success = remote_state.read_body(block_num, block_hash, body);
        CHECK(success);
        CHECK(body == BlockBody{});
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("total_difficulty with empty response from db") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        EXPECT_CALL(chain_storage, read_total_difficulty(block_hash, block_num))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<intx::uint256>> { co_return std::nullopt; }));
        const auto total_difficulty = remote_state.total_difficulty(block_num, block_hash);
        CHECK(total_difficulty == std::nullopt);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("previous_incarnation returns ok") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        const auto prev_incarnation = remote_state.previous_incarnation(address);
        CHECK(prev_incarnation == 0);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("current_canonical_block throws not implemented") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        CHECK_THROWS_AS(remote_state.current_canonical_block(), std::logic_error);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("canonical_hash throws not implemented") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        CHECK_THROWS_AS(remote_state.canonical_hash(block_num), std::logic_error);
        ioc_.stop();
        ioc_thread.join();
    }

    SECTION("state_root_hash throws not implemented") {
        std::thread ioc_thread{[&]() { ioc_.run(); }};
        const BlockNum block_num = 1'000'000;
        RemoteState remote_state(current_executor, transaction, chain_storage, block_num);
        CHECK_THROWS_AS(remote_state.state_root_hash(), std::logic_error);
        ioc_.stop();
        ioc_thread.join();
    }

    /*
        SECTION("read_code with exception") {
            boost::asio::io_context ioc;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{ioc.get_executor()};
            std::thread ioc_thread{[&ioc]() { ioc.run(); }};

            Bytes code{*from_hex("0x0608")};
            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_num = 1'000'000;
            const evmc::bytes32 code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(ioc, transaction, storage, block_num);
            auto ret_code = remote_state.read_code(code_hash);
            CHECK(ret_code == ByteView{});
            ioc.stop();
            ioc_thread.join();
        }

        SECTION("read_storage with exception") {
            boost::asio::io_context ioc;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{ioc.get_executor()};
            std::thread ioc_thread{[&ioc]() { ioc.run(); }};

            Bytes storage{*from_hex("0x0608")};
            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_num = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const evmc::bytes32 location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(ioc, transaction, storage, block_num);
            auto ret_storage = remote_state.read_storage(address, 0, location);
            CHECK(ret_storage == evmc::bytes32{});
            ioc.stop();
            ioc_thread.join();
        }

        SECTION("read_account with exception") {
            boost::asio::io_context ioc;
            boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{ioc.get_executor()};
            std::thread ioc_thread{[&ioc]() { ioc.run(); }};

            test::MockTransaction transaction; + EXPECT_CALL
            const BlockNum block_num = 1'000'000;
            evmc::address address{0x0715a7794a1dc8e42615f059dd6e406a6594651a_address};
            const RemoteChainStorage storage{transaction, backend.get()};
            RemoteState remote_state(ioc, transaction, storage, block_num);
            auto account = remote_state.read_account(address);
            CHECK(account == std::nullopt);
            ioc.stop();
            ioc_thread.join();
        }
    */

    SECTION("AsyncRemoteState::read_account for empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto account_read{spawn_and_wait(state.read_account(address))};
        CHECK(account_read == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_code with empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const evmc::bytes32 code_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const auto code_read{spawn_and_wait(state.read_code(address, code_hash))};
        CHECK(code_read.empty());
    }

    SECTION("AsyncRemoteState::read_storage with empty response from db") {
        EXPECT_CALL(transaction, get_as_of(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        const evmc::bytes32 location{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto storage_read{spawn_and_wait(state.read_storage(address, 0, location))};
        CHECK(storage_read == 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32);
    }

    SECTION("AsyncRemoteState::previous_incarnation returns ok") {
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto prev_incarnation{spawn_and_wait(state.previous_incarnation(address))};
        CHECK(prev_incarnation == 0);
    }

    SECTION("AsyncRemoteState::state_root_hash returns ok") {
        const BlockNum block_num = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, block_num};
        const auto state_root_hash{spawn_and_wait(state.state_root_hash())};
        CHECK(state_root_hash == evmc::bytes32{});
    }

    SECTION("AsyncRemoteState::current_canonical_block returns ok") {
        const TxnId txn_id = 244087591818874;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto current_canonical_block{spawn_and_wait(state.current_canonical_block())};
        CHECK(current_canonical_block == 0);
    }

    SECTION("AsyncRemoteState::total_difficulty with empty response from chain storage") {
        const TxnId txn_id = 244087591818874;
        const BlockNum block_num = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        EXPECT_CALL(chain_storage, read_total_difficulty(block_hash, block_num))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<intx::uint256>> { co_return std::nullopt; }));
        const auto total_difficulty{spawn_and_wait(state.total_difficulty(block_num, block_hash))};
        CHECK(total_difficulty == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_header with empty response from chain storage") {
        const TxnId txn_id = 244087591818874;
        const BlockNum block_num = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        EXPECT_CALL(chain_storage, read_header(block_num, block_hash))
            .WillOnce(Invoke([](Unused, Unused) -> Task<std::optional<BlockHeader>> { co_return std::nullopt; }));
        const auto block_header{spawn_and_wait(state.read_header(block_num, block_hash))};
        CHECK(block_header == std::nullopt);
    }

    SECTION("AsyncRemoteState::read_body with empty response from from chain storage") {
        const Hash block_hash{0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32};
        const TxnId txn_id = 244087591818874;
        const BlockNum block_num = 1'000'000;
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        BlockBody body;
        EXPECT_CALL(chain_storage, read_body(block_hash, block_num, body))
            .WillOnce(Invoke([](Unused, Unused, Unused) -> Task<bool> { co_return true; }));
        const auto success{spawn_and_wait(state.read_body(block_num, block_hash, body))};
        CHECK(success);
        CHECK(body == BlockBody{});
    }

    SECTION("AsyncRemoteState::canonical_hash for empty response from chain storage") {
        EXPECT_CALL(transaction, get_one(db::table::kCanonicalHashesName, _))
            .WillRepeatedly(InvokeWithoutArgs([=]() -> Task<Bytes> {
                co_return Bytes{};
            }));
        const TxnId txn_id = 244087591818874;
        const BlockNum block_num = 1'000'000;
        EXPECT_CALL(chain_storage, read_canonical_header_hash(block_num))
            .WillOnce(Invoke([](Unused) -> Task<std::optional<Hash>> { co_return std::nullopt; }));
        AsyncRemoteState state{transaction, chain_storage, txn_id};
        const auto canonical_hash{spawn_and_wait(state.canonical_hash(block_num))};
        CHECK(canonical_hash == std::nullopt);
    }
}

// Exclude gRPC tests from sanitizer builds due to data race warnings inside gRPC library
#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteStateTest, "RemoteState") {
    RemoteState remote_state(current_executor, transaction, chain_storage, 0);

    SECTION("overridden write methods do nothing") {
        CHECK_NOTHROW(remote_state.insert_block(Block{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.canonize_block(0, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.decanonize_block(0));
        CHECK_NOTHROW(remote_state.insert_receipts(0, std::vector<Receipt>{}));
        CHECK_NOTHROW(remote_state.begin_block(0, 0));
        CHECK_NOTHROW(remote_state.update_account(evmc::address{}, std::nullopt, std::nullopt));
        CHECK_NOTHROW(remote_state.update_account_code(evmc::address{}, 0, evmc::bytes32{}, ByteView{}));
        CHECK_NOTHROW(remote_state.update_storage(evmc::address{}, 0, evmc::bytes32{}, evmc::bytes32{}, evmc::bytes32{}));
        CHECK_NOTHROW(remote_state.unwind_state_changes(0));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::execution
