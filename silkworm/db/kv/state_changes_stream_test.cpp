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
#if !defined(__APPLE__) || defined(NDEBUG)
#include <csignal>
#endif  // !defined(__APPLE__) || defined(NDEBUG)
#include <future>
#include <system_error>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/kv/api/direct_client.hpp>
#include <silkworm/db/kv/grpc/client/remote_client.hpp>
#include <silkworm/db/test_util/kv_test_base.hpp>
#include <silkworm/db/test_util/test_database_context.hpp>
#if !defined(__APPLE__) || defined(NDEBUG)
#include <silkworm/infra/common/terminal.hpp>
#endif  // !defined(__APPLE__) || defined(NDEBUG)
#include <silkworm/infra/concurrency/shared_service.hpp>
#if !defined(__APPLE__) || defined(NDEBUG)
#include <silkworm/infra/concurrency/signal_handler.hpp>
#endif  // !defined(__APPLE__) || defined(NDEBUG)
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/kv_mock_fix24351.grpc.pb.h>
#include <silkworm/infra/grpc/test_util/test_runner.hpp>

#include "grpc/client/remote_client.hpp"

namespace silkworm::db::kv {

using namespace std::chrono_literals;  // NOLINT(build/namespaces)
using grpc::client::RemoteClient;
using testing::InvokeWithoutArgs;
namespace test = rpc::test;

#ifndef SILKWORM_SANITIZE
struct StateCacheTestBase : public test_util::KVTestBase {
    StateCacheTestBase() {
        add_shared_service<api::StateCache>(ioc_, std::make_shared<api::CoherentStateCache>());
    }
};

using namespace silkworm::grpc::test_util;
namespace proto = ::remote;

using StrictMockKVStub = testing::StrictMock<proto::FixIssue24351_MockKVStub>;
using RemoteClientTestRunner = TestRunner<RemoteClient, StrictMockKVStub>;

struct StateChangesStreamTest : public StateCacheTestBase {
    api::StateChangeChannelPtr channel{std::make_shared<api::StateChangeChannel>(ioc_.get_executor())};
    concurrency::Channel<api::StateChangesCall> state_changes_calls_channel{ioc_.get_executor()};
    api::ServiceRouter router{state_changes_calls_channel};
};

struct DirectStateChangesStreamTest : public StateChangesStreamTest {
    TemporaryDirectory tmp_dir;
    test_util::TestDataStore data_store{tmp_dir};
    std::shared_ptr<api::DirectService> direct_service{std::make_shared<api::DirectService>(router, data_store->ref())};
    api::DirectClient direct_client{direct_service};
    StateChangesStream stream{context_, direct_client};
};

struct RemoteStateChangesStreamTest : public StateChangesStreamTest {
    // We're not testing blocks here, so we don't care about proper block provider
    chain::BlockProvider block_provider{
        [](BlockNum, HashAsSpan, bool, Block&) -> Task<bool> { co_return false; }};
    // We're not testing blocks here, so we don't care about proper block-number-from-txn-hash provider
    chain::BlockNumFromTxnHashProvider block_num_from_txn_hash_provider{
        [](HashAsSpan) -> Task<std::optional<BlockNum>> { co_return 0; }};
    chain::BlockNumFromBlockHashProvider block_num_from_block_hash_provider{
        [](HashAsSpan) -> Task<std::optional<BlockNum>> { co_return std::nullopt; }};
    chain::CanonicalBlockHashFromNumberProvider canonical_block_hash_from_number_provider{
        [](BlockNum) -> Task<std::optional<evmc::bytes32>> { co_return 0; }};
    chain::CanonicalBodyForStorageProvider canonical_body_for_storage_provider{
        [](BlockNum) -> Task<std::optional<Bytes>> { co_return Bytes{}; }};

    RemoteClient make_remote_client(auto&& channel_or_stub) {
        return {
            std::forward<decltype(channel_or_stub)>(channel_or_stub),
            grpc_context_,
            {block_provider,
             block_num_from_txn_hash_provider,
             block_num_from_block_hash_provider,
             canonical_block_hash_from_number_provider}};
    }
};

static remote::StateChangeBatch make_batch() {
    static BlockNum block_num{14'000'010};

    remote::StateChangeBatch state_changes{};
    remote::StateChange* latest_change = state_changes.add_change_batch();
    latest_change->set_block_height(++block_num);

    return state_changes;
}

TEST_CASE_METHOD(RemoteStateChangesStreamTest, "RemoteStateChangesStreamTest::open", "[db][kv][state_changes_stream]") {
    // Set the call expectations:
    // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw call fails immediately
    expect_request_async_statechanges(/*.ok=*/false);
    // 2. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status cancelled
    EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_cancelled(grpc_context_));
    // Execute the test: opening the stream should succeed until finishes
    RemoteClient remote_client{make_remote_client(std::move(stub_))};
    StateChangesStream stream{context_, remote_client};
    std::future<void> run_completed;
    CHECK_NOTHROW(run_completed = stream.open());
    stream.close();
    CHECK_NOTHROW(run_completed.get());
}

TEST_CASE_METHOD(RemoteStateChangesStreamTest, "RemoteStateChangesStreamTest::run", "[db][kv][state_changes_stream]") {
    SECTION("stream closed-by-peer") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw)
            .WillOnce(InvokeWithoutArgs([&]() {
                // 2. AsyncReader<remote::StateChangeBatch>::StartCall call succeed
                EXPECT_CALL(*statechanges_reader_, StartCall)
                    .WillOnce([&](void* tag) {
                        agrpc::process_grpc_tag(grpc_context_, tag, /*.ok=*/true);

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

        RemoteClient remote_client{make_remote_client(std::move(stub_))};
        // remote_client.set_min_backoff_timeout(10ms);
        // remote_client.set_max_backoff_timeout(100ms);
        StateChangesStream stream{context_, remote_client};

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream.run()));
    }
    SECTION("failure in first read") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw call succeeds
        expect_request_async_statechanges(/*.ok=*/true);
        // 2. AsyncReader<remote::StateChangeBatch>::Read call fails
        EXPECT_CALL(*statechanges_reader_, Read).WillOnce(test::read_failure(grpc_context_));
        // 3. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status aborted
        EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_aborted(grpc_context_));

        RemoteClient remote_client{make_remote_client(std::move(stub_))};
        StateChangesStream stream{context_, remote_client};

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream.run()));
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

        RemoteClient remote_client{make_remote_client(std::move(stub_))};
        StateChangesStream stream{context_, remote_client};

        // Execute the test: running the stream should succeed until finishes
        CHECK_NOTHROW(spawn_and_wait(stream.run()));
    }
}

TEST_CASE_METHOD(RemoteStateChangesStreamTest, "RemoteStateChangesStreamTest::close", "[db][kv][state_changes_stream]") {
    const auto close_delay = GENERATE(0ms, 1ms, 10ms, 50ms);

    SECTION("while requesting w/ error every 10ms") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw)
            .WillRepeatedly(InvokeWithoutArgs([&]() {
                static int counter{0};
                if (counter > 0) {
                    // Recreate mocked reader for StateChanges RPC
                    statechanges_reader_ptr_ = std::make_unique<StrictMockKVStateChangesAsyncReader>();
                    statechanges_reader_ = statechanges_reader_ptr_.get();
                }
                ++counter;

                // 2. AsyncReader<>::StartCall call fails
                EXPECT_CALL(*statechanges_reader_, StartCall)
                    .WillOnce([&](void* tag) {
                        agrpc::process_grpc_tag(grpc_context_, tag, false);

                        // 3. AsyncReader<>::Finish call succeeds w/ status unavailable
                        EXPECT_CALL(*statechanges_reader_, Finish).WillOnce(test::finish_streaming_unavailable(grpc_context_));
                    });

                return statechanges_reader_ptr_.release();
            }));

        RemoteClient remote_client{make_remote_client(std::move(stub_))};
        remote_client.set_min_backoff_timeout(5ms);
        remote_client.set_max_backoff_timeout(10ms);
        StateChangesStream stream{context_, remote_client};

        // Execute the pre-condition: the stream must be running for at least for <close_delay>ms
        std::future<void> run_result;
        REQUIRE_NOTHROW(run_result = spawn(stream.run()));
        if (close_delay > 0ms) {
            sleep_for(close_delay);
        }

        // Execute the test: closing the stream should succeed
        CHECK_NOTHROW(stream.close());

        // Execute the post-condition: the running stream finishes
        REQUIRE_NOTHROW(run_result.get());
    }
    SECTION("while reading w/ error every 10ms") {
        // Set the call expectations:
        // 1. remote::KV::StubInterface::PrepareAsyncStateChangesRaw calls succeed
        EXPECT_CALL(*stub_, PrepareAsyncStateChangesRaw)
            .WillRepeatedly(InvokeWithoutArgs([&]() {
                static int counter{0};
                if (counter > 0) {
                    // Recreate mocked reader for StateChanges RPC
                    statechanges_reader_ptr_ = std::make_unique<StrictMockKVStateChangesAsyncReader>();
                    statechanges_reader_ = statechanges_reader_ptr_.get();
                }
                ++counter;

                // 2. AsyncReader<>::StartCall call succeeds
                EXPECT_CALL(*statechanges_reader_, StartCall)
                    .WillOnce([&](void* tag) {
                        agrpc::process_grpc_tag(grpc_context_, tag, /*.ok=*/true);

                        // 3. AsyncReader<remote::StateChangeBatch>::Read call fails
                        EXPECT_CALL(*statechanges_reader_, Read).WillRepeatedly(test::read_failure(grpc_context_));

                        // 4. AsyncReader<remote::StateChangeBatch>::Finish call succeeds w/ status unavailable
                        EXPECT_CALL(*statechanges_reader_, Finish)
                            .WillRepeatedly(test::finish_streaming_unavailable(grpc_context_));
                    });

                return statechanges_reader_ptr_.release();
            }));

        RemoteClient remote_client{make_remote_client(std::move(stub_))};
        remote_client.set_min_backoff_timeout(5ms);
        remote_client.set_max_backoff_timeout(10ms);
        StateChangesStream stream{context_, remote_client};

        // Execute the pre-condition: the stream must be running at least for <close_delay>ms
        std::future<void> run_result;
        REQUIRE_NOTHROW(run_result = spawn(stream.run()));
        if (close_delay > 0ms) {
            sleep_for(close_delay);
        }

        // Execute the test: closing the stream should succeed
        CHECK_NOTHROW(stream.close());

        // Execute the post-condition: the running stream finishes
        REQUIRE_NOTHROW(run_result.get());
    }
}

// Skip this test in macOS Debug build because raising signals triggers a suspension in the CLion Debug console
#if !defined(__APPLE__) || defined(NDEBUG)
TEST_CASE_METHOD(RemoteStateChangesStreamTest, "RemoteStateChangesStreamTest: signals", "[db][kv][state_changes_stream]") {
    // Skip this test if it is executed *NOT* on a TTY (e.g. CLion Run console) because it gets stuck :-(
    const bool is_terminal = is_terminal_stdout() && is_terminal_stderr();
    if (!is_terminal) {
        return;  // Silently skipped not to be counted explicitly as skipped
    }

    const auto signal_delay = GENERATE(0ms, 1ms, 10ms, 50ms);
#if defined(_WIN32)
    const auto signal_number = GENERATE(SIGBREAK, SIGTERM);
#else
    const auto signal_number = GENERATE(SIGQUIT, SIGTERM);
#endif  // defined(_WIN32)

    // We need a gRPC channel instance to stimulate the real connection scenario and trigger signal in such context
    auto make_channel_factory = []() {
        return ::grpc::CreateChannel("localhost:12345", ::grpc::InsecureChannelCredentials());
    };
    grpc::client::RemoteClient remote_client{make_remote_client(make_channel_factory)};
    remote_client.set_min_backoff_timeout(5ms);
    remote_client.set_max_backoff_timeout(10ms);
    StateChangesStream stream{context_, remote_client};
    SignalHandler::init([&stream](int) { stream.close(); }, /*silent=*/true);

    // Execute the pre-condition: the stream must be running at least for <close_delay>ms
    std::future<void> run_result;
    REQUIRE_NOTHROW(run_result = spawn(stream.run()));
    if (signal_delay > 0ms) {
        sleep_for(signal_delay);
    }

    // Execute the test: sending the signal should terminate the running stream w/o throwing exceptions
    REQUIRE(std::raise(signal_number) == 0);
    CHECK_NOTHROW(run_result.get());
}
#endif  // !defined(__APPLE__) || defined(NDEBUG)

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db::kv
