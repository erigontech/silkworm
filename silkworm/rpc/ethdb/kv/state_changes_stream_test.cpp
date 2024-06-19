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

#include "state_changes_stream.hpp"

#include <chrono>
#include <future>
#include <system_error>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/rpc/test_util/kv_test_base.hpp>

namespace silkworm::rpc::ethdb::kv {

using namespace std::chrono_literals;  // NOLINT(build/namespaces)
using testing::InvokeWithoutArgs;
using testing::Return;

class RegistrationIntervalGuard {
  public:
    explicit RegistrationIntervalGuard(std::chrono::milliseconds new_registration_interval)
        : registration_interval_(StateChangesStream::registration_interval()) {
        StateChangesStream::set_registration_interval(new_registration_interval);
    }
    ~RegistrationIntervalGuard() { StateChangesStream::set_registration_interval(registration_interval_); }

  private:
    std::chrono::milliseconds registration_interval_;
};

#ifndef SILKWORM_SANITIZE
TEST_CASE("StateChangeBatch::operator<<", "[rpc][ethdb][kv][state_changes_stream]") {
    CHECK(silkworm::test_util::null_stream() << remote::StateChangeBatch{});
}

TEST_CASE("StateChangesStream::set_registration_interval", "[rpc][ethdb][kv][state_changes_stream]") {
    CHECK(StateChangesStream::registration_interval() == kDefaultRegistrationInterval);
    constexpr std::chrono::milliseconds new_registration_interval{5'000};
    CHECK_NOTHROW(StateChangesStream::set_registration_interval(new_registration_interval));
    CHECK(StateChangesStream::registration_interval() == new_registration_interval);
    CHECK_NOTHROW(StateChangesStream::set_registration_interval(kDefaultRegistrationInterval));
    CHECK(StateChangesStream::registration_interval() == kDefaultRegistrationInterval);
}

struct StateChangesStreamTest : test_util::KVTestBase {
    StateChangesStream stream_{context_, stub_.get()};
};

static remote::StateChangeBatch make_batch() {
    static BlockNum block_height{14'000'010};

    remote::StateChangeBatch state_changes{};
    remote::StateChange* latest_change = state_changes.add_change_batch();
    latest_change->set_block_height(++block_height);

    return state_changes;
}

TEST_CASE_METHOD(StateChangesStreamTest, "StateChangesStream::open", "[rpc][ethdb][kv][state_changes_stream]") {
    RegistrationIntervalGuard guard{std::chrono::milliseconds{10}};
    // Set the call expectations:
    // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw call succeeds
    expect_request_async_statechanges(/*.ok=*/false);
    // 2. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status cancelled
    EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));
    // Execute the test: opening the stream should succeed until finishes
    std::future<void> run_completed;
    CHECK_NOTHROW(run_completed = stream_.open());
    stream_.close();
    CHECK_NOTHROW(run_completed.get());
}

TEST_CASE_METHOD(StateChangesStreamTest, "StateChangesStream::run", "[rpc][ethdb][kv][state_changes_stream]") {
    RegistrationIntervalGuard guard{std::chrono::milliseconds{10}};

    SECTION("stream closed-by-peer") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw)
            .WillOnce(InvokeWithoutArgs([&]() {
                // 2. AsyncReader<remote::StateChangeBatch>::StartCall call succeed
                EXPECT_CALL(*statechanges_reader_, StartCall)
                    .WillOnce([&](void* tag) {
                        agrpc::process_grpc_tag(grpc_context_, tag, true);

                        // 3. AsyncReader<remote::StateChangeBatch>::Read 1st/2nd/3rd calls succeed, 4th fails
                        EXPECT_CALL(*statechanges_reader_, Read)
                            .WillOnce(test::read_success_with(grpc_context_, make_batch()))
                            .WillOnce(test::read_success_with(grpc_context_, make_batch()))
                            .WillOnce(test::read_success_with(grpc_context_, make_batch()))
                            .WillOnce(test::read_failure(grpc_context_));
                        // 4. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status aborted
                        EXPECT_CALL(*statechanges_reader_, Finish)
                            .WillOnce(test::finish_streaming_aborted(grpc_context_));
                    });

                return statechanges_reader_ptr_.release();
            }));

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream_.run()));
    }
    SECTION("failure in first read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw call succeeds
        expect_request_async_statechanges(/*.ok=*/true);
        // 2. AsyncReader<remote::StateChangeBatch>::Read call fails
        EXPECT_CALL(*statechanges_reader_, Read).WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status aborted
        EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_aborted(grpc_context_));

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream_.run()));
    }
    SECTION("failure in second read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw call succeeds
        expect_request_async_statechanges(/*.ok=*/true);
        // 2. AsyncReader<remote::StateChangeBatch>::Read 1st call succeeds, 2nd call fails
        EXPECT_CALL(*statechanges_reader_, Read)
            .WillOnce(test::read_success_with(grpc_context_, make_batch()))
            .WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status aborted
        EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_aborted(grpc_context_));

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream_.run()));
    }
}

TEST_CASE_METHOD(StateChangesStreamTest, "StateChangesStream::close", "[rpc][ethdb][kv][state_changes_stream]") {
    RegistrationIntervalGuard guard{std::chrono::milliseconds{10}};

    SECTION("while requesting w/ error every 10ms") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw).WillOnce(Return(statechanges_reader_ptr_.release()));
        EXPECT_CALL(*statechanges_reader_, StartCall)
            .WillOnce([&](void* tag) {
                agrpc::process_grpc_tag(grpc_context_, tag, false);
            })
            .WillRepeatedly([&](void* tag) {
                agrpc::process_grpc_tag(grpc_context_, tag, false);

                // Recreate mocked reader for StateChanges RPC
                statechanges_reader_ptr_ = std::make_unique<StrictMockKVStateChangesAsyncReader>();
                statechanges_reader_ = statechanges_reader_ptr_.get();
            });
        // 2. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));

        // Execute the pre-condition: the stream must be running
        std::future<void> run_result;
        CHECK_NOTHROW(run_result = spawn(stream_.run()));

        // Execute the test: closing the stream should succeed
        CHECK_NOTHROW(stream_.close());

        // Execute the post-condition: the running stream finishes
        CHECK_NOTHROW(run_result.get());
    }
    SECTION("while reading w/ error every 10ms") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw).WillOnce(Return(statechanges_reader_ptr_.release()));
        EXPECT_CALL(*statechanges_reader_, StartCall)
            .WillOnce([&](void* tag) {
                agrpc::process_grpc_tag(grpc_context_, tag, false);
            })
            .WillRepeatedly([&](void* tag) {
                agrpc::process_grpc_tag(grpc_context_, tag, false);

                // Recreate mocked reader for StateChanges RPC
                statechanges_reader_ptr_ = std::make_unique<StrictMockKVStateChangesAsyncReader>();
                statechanges_reader_ = statechanges_reader_ptr_.get();
            });
        // 2. AsyncReader<remote::StateChangeBatch>::Read calls fail
        EXPECT_CALL(*statechanges_reader_, Read)
            .WillRepeatedly(test::read_failure(grpc_context_));
        // 3. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status cancelled
        EXPECT_CALL(*statechanges_reader_, Finish)
            .WillRepeatedly(test::finish_streaming_cancelled(grpc_context_));

        // Execute the pre-condition: the stream must be running at least for 30ms
        std::future<void> run_result;
        CHECK_NOTHROW(run_result = spawn(stream_.run()));
        sleep_for(30ms);

        // Execute the test: closing the stream should succeed
        CHECK_NOTHROW(stream_.close());

        // Execute the post-condition: the running stream finishes
        CHECK_NOTHROW(run_result.get());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::ethdb::kv
