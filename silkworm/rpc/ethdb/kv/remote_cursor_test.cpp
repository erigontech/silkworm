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

#include "remote_cursor.hpp"

#include <future>

#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_matcher.hpp>
#include <silkworm/rpc/test_util/kv_test_base.hpp>

namespace silkworm::rpc::ethdb::kv {

using testing::_;
using testing::AllOf;
using testing::Eq;
using testing::Expectation;
using testing::Property;

static const char* kPlainStateKey{"e0a2bd4258d2768837baa26a28fe71dc079f84c7"};
static const char* kPlainStateValue{""};

static const silkworm::Bytes kPlainStateKeyBytes{silkworm::bytes_of_string(kPlainStateKey)};
static const silkworm::Bytes kPlainStateValueBytes{silkworm::bytes_of_string(kPlainStateValue)};

static const char* kAccountChangeSetKey{"0000000000532b9f"};
static const char* kAccountChangeSetSubkey{"0000000000000000000000000000000000000000"};
static const char* kAccountChangeSetValue{"020944ed67f28fd50bb8e9"};

static const silkworm::Bytes kAccountChangeSetKeyBytes{silkworm::bytes_of_string(kAccountChangeSetKey)};
static const silkworm::Bytes kAccountChangeSetSubkeyBytes{silkworm::bytes_of_string(kAccountChangeSetSubkey)};
static const silkworm::Bytes kAccountChangeSetValueBytes{silkworm::bytes_of_string(kAccountChangeSetValue)};

struct RemoteCursorTest : test_util::KVTestBase {
    RemoteCursorTest() {
        // Set the call expectations common to all RemoteCursor tests:
        // remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(true);
        // AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ tx_id set in pair ignored
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, remote::Pair{}));

        // Execute the test preconditions: start a new Tx RPC and read first incoming message (tx_id)
        REQUIRE_NOTHROW(tx_rpc_.request_and_read(boost::asio::use_future).get());
    }

    TxRpc tx_rpc_{*stub_, grpc_context_};
    RemoteCursor remote_cursor_{tx_rpc_};
};

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::open_cursor", "[rpc][ethdb][kv][remote_cursor]") {
    SECTION("success") {
        // Set the call expectations:
        // 1. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call to open cursor on specified table succeeds
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
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.open_cursor("table1", false)),
                             boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::close_cursor", "[rpc][ethdb][kv][remote_cursor]") {
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: closing a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.close_cursor()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek", "[rpc][ethdb][kv][remote_cursor]") {
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
        KeyValue kv;
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_exact", "[rpc][ethdb][kv][remote_cursor]") {
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
        KeyValue kv;
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_exact(kPlainStateKeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::next", "[rpc][ethdb][kv][remote_cursor]") {
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
        KeyValue kv;
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::next_dup", "[rpc][ethdb][kv][remote_cursor]") {
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
        KeyValue kv;
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", true)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.next_dup()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_both", "[rpc][ethdb][kv][remote_cursor]") {
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteCursorTest, "RemoteCursor::seek_both_exact", "[rpc][ethdb][kv][remote_cursor]") {
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
        KeyValue kv;
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions: open a new cursor on specified table
        REQUIRE_NOTHROW(spawn_and_wait(remote_cursor_.open_cursor("table1", false)));

        // Execute the test: seeking a key should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_cursor_.seek_both_exact(kAccountChangeSetKeyBytes, kAccountChangeSetSubkeyBytes)), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::ethdb::kv
