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

#include "remote_database.hpp"

#include <memory>

#include <boost/system/system_error.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/kv/api/state_cache.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_matcher.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>

namespace silkworm::rpc::ethdb::kv {

class RemoteDatabaseTest : public db::test_util::KVTestBase {
  protected:
    // RemoteDatabase holds the KV stub by std::unique_ptr, so we cannot rely on mock stub from base class
    StrictMockKVStub* kv_stub_ = new StrictMockKVStub;
    RemoteDatabase remote_db_{&backend_, &state_cache_, grpc_context_, std::unique_ptr<StrictMockKVStub>{kv_stub_}};

  private:
    test::BackEndMock backend_;
    db::kv::api::CoherentStateCache state_cache_;
};

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(RemoteDatabaseTest, "RemoteDatabase::begin", "[rpc][ethdb][kv][remote_database]") {
    using namespace testing;  // NOLINT(build/namespaces)

    SECTION("success") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(*kv_stub_, true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call succeeds setting the specified transaction ID
        remote::Pair pair;
        pair.set_view_id(4);
        EXPECT_CALL(reader_writer_, Read).WillOnce(test::read_success_with(grpc_context_, pair));

        // Execute the test: RemoteDatabase::begin should return transaction w/ expected transaction ID
        const auto txn = spawn_and_wait(remote_db_.begin());
        CHECK(txn->view_id() == 4);
    }

    SECTION("open failure") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call fails
        expect_request_async_tx(*kv_stub_, /*ok=*/false);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call returns w/ failure
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: RemoteDatabase::begin should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_db_.begin()),
                             boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }

    SECTION("read failure") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncTxRaw call succeeds
        expect_request_async_tx(*kv_stub_, true);
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::Read call fails
        EXPECT_CALL(reader_writer_, Read).WillOnce([&](auto*, void* tag) {
            agrpc::process_grpc_tag(grpc_context_, tag, /*ok=*/false);
        });
        // 2. AsyncReaderWriter<remote::Cursor, remote::Pair>::WritesDone call returns w/ failure
        EXPECT_CALL(reader_writer_, WritesDone).WillOnce(test::writes_done_failure(grpc_context_));
        // 3. AsyncReaderWriter<remote::Cursor, remote::Pair>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(reader_writer_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the test: RemoteDatabase::begin should raise an exception w/ expected gRPC status code
        CHECK_THROWS_MATCHES(spawn_and_wait(remote_db_.begin()),
                             boost::system::system_error,
                             test::exception_has_cancelled_grpc_status_code());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::ethdb::kv
