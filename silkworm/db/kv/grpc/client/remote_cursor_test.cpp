// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "remote_cursor.hpp"

#include <future>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/infra/grpc/common/errors.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_matcher.hpp>

namespace silkworm::db::kv::grpc::client {

using testing::_;
using testing::AllOf;
using testing::Eq;
using testing::Expectation;
using testing::Property;
namespace test = rpc::test;

// The following constants must stay as std::string/Bytes because gRPC bindings require std::string
static const std::string kPlainStateKey{"e0a2bd4258d2768837baa26a28fe71dc079f84c7"};
static const std::string kPlainStateValue;

static const silkworm::Bytes kPlainStateKeyBytes{string_view_to_byte_view(kPlainStateKey)};
static const silkworm::Bytes kPlainStateValueBytes{string_view_to_byte_view(kPlainStateValue)};

static const std::string kAccountChangeSetKey{"0000000000532b9f"};
static const std::string kAccountChangeSetSubkey{"0000000000000000000000000000000000000000"};
static const std::string kAccountChangeSetValue{"020944ed67f28fd50bb8e9"};

static const silkworm::Bytes kAccountChangeSetKeyBytes{string_to_bytes(kAccountChangeSetKey)};
static const silkworm::Bytes kAccountChangeSetSubkeyBytes{string_to_bytes(kAccountChangeSetSubkey)};
static const silkworm::Bytes kAccountChangeSetValueBytes{string_to_bytes(kAccountChangeSetValue)};

class RemoteCursorTest : public test_util::KVTestBase {
  public:
    RemoteCursorTest() {
        // Set the call expectations common to all RemoteCursor tests:
        // remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ tx_id in Pair ignored
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, remote::Pair{}));
    }

    // Execute the test preconditions: start a new Tx RPC and read first incoming message (tx_id)
    Task<::remote::Pair> start_and_read_tx_id() {
        if (!co_await tx_rpc_.start(*stub_)) {
            const auto status = co_await tx_rpc_.finish();
            throw boost::system::system_error{rpc::to_system_code(status.error_code())};
        }
        ::remote::Pair tx_id_pair;
        if (!co_await tx_rpc_.read(tx_id_pair)) {
            const auto status = co_await tx_rpc_.finish();
            throw boost::system::system_error{rpc::to_system_code(status.error_code())};
        }
        co_return tx_id_pair;
    }

  protected:
    RemoteCursor remote_cursor_{tx_rpc_};

  private:
    TxRpc tx_rpc_{grpc_context_};
};

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::open_cursor", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor on the specified table succeeds
        EXPECT_CALL(reader_writer_, Write(
                                        AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
            .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, open_pair));

        // Execute the test: opening a cursor on specified table should succeed and cursor should have expected cursor ID
        CHECK_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));
        CHECK(remote_cursor_.cursor_id() == 3);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor on specified table fails
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_failure(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.open_cursor("table1", false)),
                             boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor on specified table succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call fails
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status aborted
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.open_cursor("table1", false)),
                             boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::close_cursor", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to close cursor w/ specified cursor ID succeeds
        EXPECT_CALL(reader_writer_, Write(
                                        AllOf(Property(&remote::Cursor::op, Eq(remote::Op::CLOSE)), Property(&remote::Cursor::cursor, Eq(3))), _))
            .After(open)
            .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, remote::Pair{}));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: closing a cursor should succeed and reset the cursor ID
        CHECK_NOTHROW(spawn_and_wait(remote_cursor_.close_cursor()));
        CHECK(remote_cursor_.cursor_id() == 0);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to close cursor w/ specified cursor ID fails
        EXPECT_CALL(reader_writer_, Write(
                                        AllOf(Property(&remote::Cursor::op, Eq(remote::Op::CLOSE)), Property(&remote::Cursor::cursor, Eq(3))), _))
            .After(open)
            .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: closing a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.close_cursor()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to close cursor w/ specified cursor ID succeeds
        EXPECT_CALL(reader_writer_, Write(
                                        AllOf(Property(&remote::Cursor::op, Eq(remote::Op::CLOSE)), Property(&remote::Cursor::cursor, Eq(3))), _))
            .After(open)
            .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: closing a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.close_cursor()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair seek_pair;
        seek_pair.set_cursor_id(3);
        seek_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, seek_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.seek(kPlainStateKeyBytes)));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID fails
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_exact", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair seek_pair;
        seek_pair.set_cursor_id(3);
        seek_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, seek_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.seek_exact(kPlainStateKeyBytes)));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID fails
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_exact(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kPlainStateKey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_exact(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::first", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to first w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::FIRST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair first_pair;
        first_pair.set_cursor_id(3);
        first_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, first_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking first key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.first()));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to first w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::FIRST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_aborted(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking first key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.first()), boost::system::system_error, test::exception_has_aborted_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to first w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::FIRST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish fails succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.first()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::last", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to last w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::LAST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair first_pair;
        first_pair.set_cursor_id(3);
        first_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, first_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking last key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.last()));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to last w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::LAST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_aborted(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking last key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.last()), boost::system::system_error, test::exception_has_aborted_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to last w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_,
                                       Write(AllOf(Property(&remote::Cursor::op, Eq(remote::Op::LAST)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.last()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::next", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair next_pair;
        next_pair.set_cursor_id(3);
        next_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, next_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking next key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.next()));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID fails
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking next key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::next_dup", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN_DUP_SORT)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT_DUP)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair next_pair;
        next_pair.set_cursor_id(3);
        next_pair.set_k(kPlainStateKey);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, next_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", true)));

        // Execute the test: seeking next key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.next_dup()));
        CHECK(kv.key == kPlainStateKeyBytes);
        CHECK(kv.value == kPlainStateValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN_DUP_SORT)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID fails
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT_DUP)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", true)));

        // Execute the test: seeking next key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next_dup()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN_DUP_SORT)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek next w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::NEXT_DUP)), Property(&remote::Cursor::cursor, Eq(3))), _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", true)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next_dup()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_both", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair seek_pair;
        seek_pair.set_cursor_id(3);
        seek_pair.set_k(kAccountChangeSetKey);
        seek_pair.set_v(kAccountChangeSetValue);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, seek_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should succeed and return the expected value
        silkworm::Bytes value;
        CHECK_NOTHROW(value = spawn_and_wait(remote_cursor_.seek_both(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)));
        CHECK(value == kAccountChangeSetValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_both_exact", "[rpc][ethdb][kv][remote_cursor]") {
    // Execute the test common preconditions: start a new Tx RPC and read first incoming message (tx_id)
    REQUIRE_NOTHROW(spawn_and_wait(start_and_read_tx_id()));

    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        remote::Pair seek_pair;
        seek_pair.set_cursor_id(3);
        seek_pair.set_k(kAccountChangeSetKey);
        seek_pair.set_v(kAccountChangeSetValue);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_success_with(grpc_context_, seek_pair));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should succeed and return the expected value
        api::KeyValue kv;
        CHECK_NOTHROW(kv = spawn_and_wait(remote_cursor_.seek_both_exact(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)));
        CHECK(kv.key == kAccountChangeSetKeyBytes);
        CHECK(kv.value == kAccountChangeSetValueBytes);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified cursor ID
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both_exact(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor succeeds
        Expectation open = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::OPEN)), Property(&remote::Cursor::bucket_name, Eq("table1"))), _))
                               .WillOnce(test::write_success(grpc_context_));
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to seek w/ specified cursor ID succeeds
        Expectation seek = EXPECT_CALL(reader_writer_, Write(
                                                           AllOf(Property(&remote::Cursor::op, Eq(remote::Op::SEEK_BOTH_EXACT)), Property(&remote::Cursor::cursor, Eq(3)),
                                                                 Property(&remote::Cursor::k, Eq(kAccountChangeSetKey)), Property(&remote::Cursor::v, Eq(kAccountChangeSetSubkey))),
                                                           _))
                               .After(open)
                               .WillOnce(test::write_success(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds setting the specified cursor ID, 2nd fails
        remote::Pair open_pair;
        open_pair.set_cursor_id(3);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, open_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both_exact(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db::kv::grpc::client
