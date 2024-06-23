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

#include "remote_transaction.hpp"

#include <system_error>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>

#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_matcher.hpp>

#include "../../api/state_cache.hpp"

namespace silkworm::db::kv::grpc::client {

using testing::_;
namespace test = rpc::test;

struct RemoteTransactionTest : test_util::KVTestBase {
    api::CoherentStateCache state_cache_;
    RemoteTransaction remote_tx_{*stub_,
                                 grpc_context_,
                                 &state_cache_,
                                 {},
                                 {}};
};

#ifndef SILKWORM_SANITIZE

static remote::Pair make_fake_tx_created_pair() {
    remote::Pair pair;
    pair.set_tx_id(1);
    pair.set_view_id(4);
    return pair;
}

bool ensure_fake_tx_created_tx_id(const RemoteTransaction& remote_tx) {
    return remote_tx.tx_id() == 1;
}

bool ensure_fake_tx_created_view_id(const RemoteTransaction& remote_tx) {
    return remote_tx.view_id() == 4;
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::open", "[rpc][ethdb][kv][remote_transaction]") {
    SECTION("success") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified transaction ID
        remote::Pair pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, pair));

        // Execute the test: opening a transaction should succeed and transaction should have expected transaction ID
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.open()));
        CHECK(ensure_fake_tx_created_tx_id(remote_tx_));
        CHECK(ensure_fake_tx_created_view_id(remote_tx_));
    }
    SECTION("failure in request") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call fails
        expect_request_async_tx(/*ok=*/false);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a transaction should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.open()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call fails
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a transaction should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.open()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::close", "[rpc][ethdb][kv][remote_transaction]") {
    SECTION("throw w/o open") {
        // Execute the test: closing the transaction should throw
        CHECK_THROWS_AS(spawn_and_wait(remote_tx_.close()), boost::system::system_error);
    }
    SECTION("success w/ open w/o cursor in table") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ expected transaction ID set in pair
        remote::Pair pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected tx_id
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: closing the transaction should succeed and transaction should have zero transaction ID
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
        CHECK(remote_tx_.tx_id() == 0);
        CHECK(remote_tx_.view_id() == 0);
    }
    SECTION("success w/ open w/ cursor in table") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ expected transaction ID set in pair
        remote::Pair pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).Times(2).WillRepeatedly(test::read_success_with(grpc_context_, pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));
        // open a cursor within such transaction
        const auto cursor = spawn_and_wait(remote_tx_.cursor("table1"));
        REQUIRE(cursor != nullptr);

        // Execute the test: closing the transaction should succeed and transaction should have zero transaction ID
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
        CHECK(remote_tx_.view_id() == 0);
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ expected transaction ID set in pair
        remote::Pair pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: closing the transaction should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in finish") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ expected transaction ID set in pair
        remote::Pair pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, pair));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call fails
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_error(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: closing the transaction should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error, test::exception_has_unknown_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::cursor", "[rpc][ethdb][kv][remote_transaction]") {
    SECTION("throw w/o open") {
        // Execute the test: getting cursor from the transaction should throw
        CHECK_THROWS_AS(spawn_and_wait(remote_tx_.cursor("table1")), boost::system::system_error);
    }
    SECTION("success") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed w/ specified transaction and cursor IDs
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        tx_id_pair.set_view_id(4);
        remote::Pair cursor_id_pair;
        cursor_id_pair.set_cursor_id(0x23);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair))
            .WillOnce(test::read_success_with(grpc_context_, cursor_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test:
        // 1. opening a cursor should succeed and cursor should have expected cursor ID
        std::shared_ptr<api::Cursor> cursor1;
        CHECK_NOTHROW(cursor1 = spawn_and_wait(remote_tx_.cursor("table1")));
        CHECK(cursor1->cursor_id() == 0x23);
        // 2. opening another cursor on the same table should succeed and cursor should have expected cursor ID
        std::shared_ptr<api::Cursor> cursor2;
        CHECK_NOTHROW(cursor2 = spawn_and_wait(remote_tx_.cursor("table1")));
        CHECK(cursor2->cursor_id() == 0x23);

        // Execute the test postconditions:
        // close the transaction succeeds
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds w/ specified transaction ID, 2nd call fails
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.cursor("table1")), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());

        // Execute the test postconditions:
        // close the transaction raises an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ specified transaction ID
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, tx_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call fails
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.cursor("table1")), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());

        // Execute the test postconditions:
        // close the transaction raises an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::cursor_dup_sort", "[rpc][ethdb][kv][remote_transaction]") {
    SECTION("throw w/o open") {
        // Execute the test preconditions: none

        // Execute the test: getting cursor_dup_sort from the transaction should throw
        CHECK_THROWS_AS(spawn_and_wait(remote_tx_.cursor_dup_sort("table1")), boost::system::system_error);

        // Execute the test postconditions:
        // close the transaction raises an exception
        CHECK_THROWS_AS(spawn_and_wait(remote_tx_.close()), boost::system::system_error);
    }
    SECTION("success") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed w/ specified transaction and cursor IDs
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        remote::Pair cursor_id_pair;
        cursor_id_pair.set_cursor_id(0x23);
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair))
            .WillOnce(test::read_success_with(grpc_context_, cursor_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test:
        // 1. opening a cursor should succeed and cursor should have expected cursor ID
        std::shared_ptr<api::Cursor> cursor1;
        CHECK_NOTHROW(cursor1 = spawn_and_wait(remote_tx_.cursor_dup_sort("table1")));
        CHECK(cursor1->cursor_id() == 0x23);
        // 2. opening another cursor on the same table should succeed and cursor should have expected cursor ID
        std::shared_ptr<api::Cursor> cursor2;
        CHECK_NOTHROW(cursor2 = spawn_and_wait(remote_tx_.cursor_dup_sort("table1")));
        CHECK(cursor2->cursor_id() == 0x23);

        // Execute the test postconditions:
        // close the transaction succeeds
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
    }
    SECTION("failure in read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read 1st call succeeds w/ specified transaction ID, 2nd call fails
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair))
            .WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call succeeds
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.cursor_dup_sort("table1")), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());

        // Execute the test postconditions:
        // close the transaction raises an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
    SECTION("failure in write") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds w/ specified transaction ID
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, tx_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Write call fails
        EXPECT_CALL(reader_writer_, Write(_, _)).WillOnce(test::write_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: opening a cursor should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.cursor_dup_sort("table1")), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());

        // Execute the test postconditions:
        // close the transaction raises an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.close()), boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db::kv::grpc::client
