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

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_matcher.hpp>

#include "../test_util/sample_protos.hpp"

namespace silkworm::db::kv::grpc::client {

using testing::_;
namespace proto = ::remote;
namespace test = rpc::test;

class RemoteTransactionTest : public db::test_util::KVTestBase {
  protected:
    RemoteTransaction remote_tx_{*stub_,
                                 grpc_context_,
                                 chain::Providers{}};
};

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

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::open", "[db][kv][grpc][client][remote_transaction]") {
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
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
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
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_)).WillOnce(test::writes_done_failure(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: opening a transaction should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_tx_.open()), boost::system::system_error, test::exception_has_cancelled_grpc_status_code());
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::close", "[db][kv][grpc][client][remote_transaction]") {
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

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::cursor", "[db][kv][grpc][client][remote_transaction]") {
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_))
            .WillOnce(test::writes_done_failure(grpc_context_))
            .WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish)
            .WillOnce(test::finish_streaming_cancelled(grpc_context_))
            .WillOnce(test::finish_streaming_cancelled(grpc_context_));

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
        EXPECT_CALL(reader_writer_, Finish)
            .WillOnce(test::finish_streaming_cancelled(grpc_context_))
            .WillOnce(test::finish_streaming_cancelled(grpc_context_));

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

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::cursor_dup_sort", "[db][kv][grpc][client][remote_transaction]") {
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
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call fails
        EXPECT_CALL(reader_writer_, WritesDone(_))
            .WillOnce(test::writes_done_failure(grpc_context_))
            .WillOnce(test::writes_done_failure(grpc_context_));
        // 5. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish)
            .WillOnce(test::finish_streaming_cancelled(grpc_context_))
            .WillOnce(test::finish_streaming_cancelled(grpc_context_));

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
        EXPECT_CALL(reader_writer_, Finish)
            .WillOnce(test::finish_streaming_cancelled(grpc_context_))
            .WillOnce(test::finish_streaming_cancelled(grpc_context_));

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

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::get_latest", "[db][kv][grpc][client][remote_transaction]") {
    using db::kv::test_util::sample_proto_get_latest_response;

    auto get_latest = [&]() -> Task<api::GetLatestResult> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::GetLatestRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::GetLatestRequest request;
        const api::GetLatestResult result = co_await remote_tx_.get_latest(std::move(request));
#else
        const api::GetLatestResult result = co_await remote_tx_.get_latest(api::GetLatestRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return result;
    };

    rpc::test::StrictMockAsyncResponseReader<proto::GetLatestReply> reader;
    EXPECT_CALL(*stub_, AsyncGetLatestRaw).WillOnce(testing::Return(&reader));

    api::GetLatestResult result;

    SECTION("call get_latest and get result") {
        proto::GetLatestReply reply{sample_proto_get_latest_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        CHECK_NOTHROW((result = spawn_and_wait(get_latest)));
        CHECK(result.success);
        CHECK(result.value == from_hex("ff00ff00"));
    }
    SECTION("call get_latest and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        CHECK_NOTHROW((result = spawn_and_wait(get_latest)));
        CHECK_FALSE(result.success);
        CHECK(result.value.empty());
    }
    SECTION("call get_latest and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS(spawn_and_wait(get_latest), boost::system::system_error);
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::get_as_of", "[db][kv][grpc][client][remote_transaction]") {
    using db::kv::test_util::sample_proto_get_as_of_response;

    auto get_as_of = [&]() -> Task<api::GetAsOfResult> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::GetAsOfRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::GetAsOfRequest request;
        const api::GetAsOfResult result = co_await remote_tx_.get_as_of(std::move(request));
#else
        const api::GetAsOfResult result = co_await remote_tx_.get_as_of(api::GetAsOfRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return result;
    };

    rpc::test::StrictMockAsyncResponseReader<proto::GetLatestReply> reader;
    EXPECT_CALL(*stub_, AsyncGetLatestRaw).WillOnce(testing::Return(&reader));

    api::GetAsOfResult result;

    SECTION("call get_as_of and get result") {
        proto::GetLatestReply reply{sample_proto_get_as_of_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        CHECK_NOTHROW((result = spawn_and_wait(get_as_of)));
        CHECK(result.success);
        CHECK(result.value == from_hex("ff00ff00"));
    }
    SECTION("call get_as_of and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        CHECK_NOTHROW((result = spawn_and_wait(get_as_of)));
        CHECK_FALSE(result.success);
        CHECK(result.value.empty());
    }
    SECTION("call get_as_of and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS(spawn_and_wait(get_as_of), boost::system::system_error);
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::history_seek", "[db][kv][grpc][client][remote_transaction]") {
    using db::kv::test_util::sample_proto_history_seek_response;

    auto history_seek = [&]() -> Task<api::HistoryPointResult> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::HistoryPointRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::HistoryPointRequest request;
        const api::HistoryPointResult result = co_await remote_tx_.history_seek(std::move(request));
#else
        const api::HistoryPointResult result = co_await remote_tx_.history_seek(api::HistoryPointRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return result;
    };

    rpc::test::StrictMockAsyncResponseReader<proto::HistorySeekReply> reader;
    EXPECT_CALL(*stub_, AsyncHistorySeekRaw).WillOnce(testing::Return(&reader));

    api::HistoryPointResult result;

    SECTION("call history_seek and get result") {
        proto::HistorySeekReply reply{sample_proto_history_seek_response()};
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_with(grpc_context_, std::move(reply)));

        CHECK_NOTHROW((result = spawn_and_wait(history_seek)));
        CHECK(result.success);
        CHECK(result.value == from_hex("ff00ff00"));
    }
    SECTION("call history_seek and get empty result") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_ok(grpc_context_));

        CHECK_NOTHROW((result = spawn_and_wait(history_seek)));
        CHECK_FALSE(result.success);
        CHECK(result.value.empty());
    }
    SECTION("call history_seek and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(rpc::test::finish_cancelled(grpc_context_));

        CHECK_THROWS_AS(spawn_and_wait(history_seek), boost::system::system_error);
    }
}

static ::remote::IndexRangeReply make_index_range_reply(const api::ListOfTimestamp& timestamps, bool has_more) {
    proto::IndexRangeReply reply;
    for (const auto ts : timestamps) {
        reply.add_timestamps(static_cast<uint64_t>(ts));
    }
    reply.set_next_page_token(has_more ? "token" : "");
    return reply;
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::index_range", "[db][kv][grpc][client][remote_transaction]") {
    auto flatten_index_range = [&]() -> Task<api::ListOfTimestamp> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::IndexRangeRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::IndexRangeRequest request;
        auto paginated_timestamps = co_await remote_tx_.index_range(std::move(request));
#else
        auto paginated_timestamps = co_await remote_tx_.index_range(api::IndexRangeRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return co_await paginated_to_vector(paginated_timestamps);
    };
    rpc::test::StrictMockAsyncResponseReader<proto::IndexRangeReply> reader;
    SECTION("throw on error") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncIndexRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncIndexRangeRaw).WillOnce(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call fails
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_error_aborted(grpc_context_, proto::IndexRangeReply{}));
        // Execute the test: trying to *use* index_range lazy result should throw
        CHECK_THROWS_AS(spawn_and_wait(flatten_index_range), boost::system::system_error);
    }
    SECTION("success: empty") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncIndexRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncIndexRangeRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_index_range_reply({}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_index_range).empty());
    }
    SECTION("success: one page") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncIndexRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncIndexRangeRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_index_range_reply({19}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_index_range) == api::ListOfTimestamp{19});
    }
    SECTION("success: more than one page") {
        // Set the call expectations: [just once let's do the whole procedure by calling Tx first]
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed w/ specified transaction and cursor IDs
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));
        // 5. remote::KV::StubInterface::AsyncIndexRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncIndexRangeRaw).WillRepeatedly(Return(&reader));
        // 6. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_index_range_reply({1, 2, 3}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_index_range_reply({4, 5, 6}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_index_range_reply({7}, /*has_more*/ false)));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_index_range) == api::ListOfTimestamp{1, 2, 3, 4, 5, 6, 7});

        // Execute the test postconditions:
        // close the transaction succeeds
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
    }
}

static proto::Pairs make_key_value_range_reply(const std::vector<api::KeyValue>& keys_and_values, bool has_more) {
    proto::Pairs reply;
    for (const auto& kv : keys_and_values) {
        reply.add_keys(bytes_to_string(kv.key));
        reply.add_values(bytes_to_string(kv.value));
    }
    reply.set_next_page_token(has_more ? "token" : "");
    return reply;
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::history_range", "[db][kv][grpc][client][remote_transaction]") {
    const api::KeyValue kv1{*from_hex("0011FF0011AA"), *from_hex("0011")};
    const api::KeyValue kv2{*from_hex("0011FF0011BB"), *from_hex("0022")};
    const api::KeyValue kv3{*from_hex("0011FF0011CC"), *from_hex("0033")};

    auto flatten_history_range = [&]() -> Task<std::vector<api::KeyValue>> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::HistoryRangeRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::HistoryRangeRequest request;
        auto paginated_keys_and_values = co_await remote_tx_.history_range(std::move(request));
#else
        auto paginated_keys_and_values = co_await remote_tx_.history_range(api::HistoryRangeRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return co_await paginated_to_vector(paginated_keys_and_values);
    };
    rpc::test::StrictMockAsyncResponseReader<proto::Pairs> reader;
    SECTION("throw on error") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncHistoryRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncHistoryRangeRaw).WillOnce(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call fails
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_error_aborted(grpc_context_, proto::Pairs{}));
        // Execute the test: trying to *use* index_range lazy result should throw
        CHECK_THROWS_AS(spawn_and_wait(flatten_history_range), boost::system::system_error);
    }
    SECTION("success: empty") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncHistoryRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncHistoryRangeRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_history_range).empty());
    }
    SECTION("success: one page") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncHistoryRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncHistoryRangeRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv1}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_history_range) == std::vector<api::KeyValue>{kv1});
    }
    SECTION("success: more than one page") {
        // Set the call expectations: [just once let's do the whole procedure by calling Tx first]
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed w/ specified transaction and cursor IDs
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));
        // 5. remote::KV::StubInterface::AsyncHistoryRangeRaw call succeeds
        EXPECT_CALL(*stub_, AsyncHistoryRangeRaw).WillRepeatedly(Return(&reader));
        // 6. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv1, kv2}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv2, kv1}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv3}, /*has_more*/ false)));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_history_range) == std::vector<api::KeyValue>{kv1, kv2, kv2, kv1, kv3});

        // Execute the test postconditions:
        // close the transaction succeeds
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
    }
}

TEST_CASE_METHOD(RemoteTransactionTest, "RemoteTransaction::range_as_of", "[db][kv][grpc][client][remote_transaction]") {
    const api::KeyValue kv1{*from_hex("0011FF0011AA"), *from_hex("0011")};
    const api::KeyValue kv2{*from_hex("0011FF0011BB"), *from_hex("0022")};
    const api::KeyValue kv3{*from_hex("0011FF0011CC"), *from_hex("0033")};

    auto flatten_domain_range = [&]() -> Task<std::vector<api::KeyValue>> {
#if __GNUC__ < 13 && !defined(__clang__)  // Clang compiler defines __GNUC__ as well
        // Before GCC 13, we must avoid passing api::DomainRangeRequest as temporary because co_await-ing expressions
        // that involve compiler-generated constructors binding references to pr-values seems to trigger this bug:
        // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100611
        api::DomainRangeRequest request;
        auto paginated_keys_and_values = co_await remote_tx_.range_as_of(std::move(request));
#else
        auto paginated_keys_and_values = co_await remote_tx_.range_as_of(api::DomainRangeRequest{});
#endif  // #if __GNUC__ < 13 && !defined(__clang__)
        co_return co_await paginated_to_vector(paginated_keys_and_values);
    };
    rpc::test::StrictMockAsyncResponseReader<proto::Pairs> reader;
    SECTION("throw on error") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncRangeAsOfRaw call succeeds
        EXPECT_CALL(*stub_, AsyncRangeAsOfRaw).WillOnce(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call fails
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_error_aborted(grpc_context_, proto::Pairs{}));
        // Execute the test: trying to *use* index_range lazy result should throw
        CHECK_THROWS_AS(spawn_and_wait(flatten_domain_range), boost::system::system_error);
    }
    SECTION("success: empty") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncRangeAsOfRaw call succeeds
        EXPECT_CALL(*stub_, AsyncRangeAsOfRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_domain_range).empty());
    }
    SECTION("success: one page") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::AsyncRangeAsOfRaw call succeeds
        EXPECT_CALL(*stub_, AsyncRangeAsOfRaw).WillRepeatedly(Return(&reader));
        // 2. AsyncResponseReader<>::Finish call succeeds
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv1}, /*has_more*/ false)));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_domain_range) == std::vector<api::KeyValue>{kv1});
    }
    SECTION("success: more than one page") {
        // Set the call expectations: [just once let's do the whole procedure by calling Tx first]
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(/*ok=*/true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read calls succeed w/ specified transaction and cursor IDs
        remote::Pair tx_id_pair{make_fake_tx_created_pair()};
        EXPECT_CALL(reader_writer_, Read)
            .WillOnce(test::read_success_with(grpc_context_, tx_id_pair));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call succeeds
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_success(grpc_context_));
        // 4. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status OK
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_ok(grpc_context_));
        // 5. remote::KV::StubInterface::AsyncRangeAsOfRaw call succeeds
        EXPECT_CALL(*stub_, AsyncRangeAsOfRaw).WillRepeatedly(Return(&reader));
        // 6. AsyncResponseReader<>::Finish call succeeds 3 times
        EXPECT_CALL(reader, Finish)
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv1, kv2}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv2, kv1}, /*has_more*/ true)))
            .WillOnce(test::finish_with(grpc_context_, make_key_value_range_reply({kv3}, /*has_more*/ false)));

        // Execute the test preconditions:
        // open a new transaction w/ expected transaction ID
        REQUIRE_NOTHROW(spawn_and_wait(remote_tx_.open()));
        REQUIRE(ensure_fake_tx_created_tx_id(remote_tx_));
        REQUIRE(ensure_fake_tx_created_view_id(remote_tx_));

        // Execute the test: call index_range and flatten the data matches the expected data
        CHECK(spawn_and_wait(flatten_domain_range) == std::vector<api::KeyValue>{kv1, kv2, kv2, kv1, kv3});

        // Execute the test postconditions:
        // close the transaction succeeds
        CHECK_NOTHROW(spawn_and_wait(remote_tx_.close()));
    }
}

}  // namespace silkworm::db::kv::grpc::client
