/*
   Copyright 2022 The Silkworm Authors

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

#include "call.hpp"

#include <ostream>

#include <catch2/catch.hpp>

#include <remote/ethbackend.grpc.pb.h>
#include <remote/kv.grpc.pb.h>

namespace silkworm::rpc {

// Factory function creating one null output stream (all characters are discarded)
inline std::ostream& null_stream() {
    static struct null_buf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct null_strm : public std::ostream {
        null_strm() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

// Exclude gRPC tests from sanitizer builds due to data race warnings
#ifndef SILKWORM_SANITIZE
TEST_CASE("AsyncCall", "[silkworm][rpc][client][call]") {
    class FakeCall : public AsyncCall {
      public:
        explicit FakeCall(grpc::CompletionQueue* queue) : AsyncCall(queue) {}
    };

    grpc::CompletionQueue queue;

    SECTION("AsyncCall::AsyncCall") {
        FakeCall call{&queue};
        CHECK(call.peer().empty());
        CHECK(call.start_time() <= std::chrono::steady_clock::now());
        CHECK(call.end_time() <= std::chrono::steady_clock::now());
        CHECK(call.latency() == call.end_time() - call.start_time());
        CHECK(call.status().ok());
        CHECK_NOTHROW(call.cancel());
    }
}

static const std::string kTestAddressUri{"localhost:12345"};

TEST_CASE("AsyncUnaryCall", "[silkworm][rpc][client][call]") {
    class FakeUnaryCall : public AsyncUnaryCall<
        remote::NetVersionRequest,
        remote::NetVersionReply,
        remote::ETHBACKEND::StubInterface,
        &remote::ETHBACKEND::StubInterface::PrepareAsyncNetVersion> {
      public:
        explicit FakeUnaryCall(grpc::CompletionQueue* queue, remote::ETHBACKEND::StubInterface* stub, CompletionFunc func = {})
            : AsyncUnaryCall(queue, stub, func) {}

        bool finished() const { return finished_; }

        void trigger_finish(bool ok) {
            finish_processor_(ok);
        }

      protected:
        void handle_finish(bool /*ok*/) override {
            finished_ = true;
        }

      private:
        bool finished_{false};
    };

    grpc::CompletionQueue queue;
    auto channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto stub_ptr = remote::ETHBACKEND::NewStub(channel, grpc::StubOptions{});

    SECTION("AsyncUnaryCall::AsyncUnaryCall 1") {
        FakeUnaryCall call{&queue, stub_ptr.get(), [](auto* /*call*/) {}};
        CHECK(call.peer().empty());
        CHECK(call.start_time() <= std::chrono::steady_clock::now());
        CHECK(call.status().ok());
        CHECK_NOTHROW(call.cancel());
    }

    SECTION("AsyncUnaryCall::AsyncUnaryCall 2") {
        FakeUnaryCall call{&queue, stub_ptr.get()};
        CHECK(call.peer().empty());
        CHECK(call.start_time() <= std::chrono::steady_clock::now());
        CHECK(call.status().ok());
        CHECK_NOTHROW(call.cancel());
    }

    SECTION("AsyncUnaryCall::handle_finish") {
        FakeUnaryCall call{&queue, stub_ptr.get()};
        CHECK(!call.finished());
        CHECK_NOTHROW(call.trigger_finish(true));
        CHECK(call.finished());
    }
}

TEST_CASE("AsyncServerStreamingCall", "[silkworm][rpc][client][call]") {
    class FakeServerStreamingCall : public AsyncServerStreamingCall<
        remote::StateChangeRequest,
        remote::StateChangeBatch,
        remote::KV::StubInterface,
        &remote::KV::StubInterface::PrepareAsyncStateChanges> {
      public:
        explicit FakeServerStreamingCall(grpc::CompletionQueue* queue, remote::KV::StubInterface* stub)
            : AsyncServerStreamingCall(queue, stub) {}

        bool read_called() const { return read_called_; }

        bool read_completed() const { return read_completed_; }

        bool finish_called() const { return finish_called_; }

        bool finished() const { return finished_; }

        void trigger_start(bool ok) {
            start_processor_(ok);
        }

        void trigger_read(bool ok) {
            read_processor_(ok);
        }

        void trigger_finish(bool ok) {
            finish_processor_(ok);
        }

      protected:
        void read() override {
            read_called_ = true;
        }

        void finish() override {
            finish_called_ = true;
        }

        void handle_read() override {
            read_completed_ = true;
        }

        void handle_finish() override {
            finished_ = true;
        }

      private:
        bool read_called_{false};
        bool read_completed_{false};
        bool finish_called_{false};
        bool finished_{false};
    };

    grpc::CompletionQueue queue;
    auto channel = grpc::CreateChannel(kTestAddressUri, grpc::InsecureChannelCredentials());
    auto stub_ptr = remote::KV::NewStub(channel, grpc::StubOptions{});

    SECTION("AsyncServerStreamingCall::process_start OK") {
        FakeServerStreamingCall call{&queue, stub_ptr.get()};
        CHECK(!call.read_called());
        CHECK_NOTHROW(call.trigger_start(true));
        CHECK(call.read_called());
    }

    SECTION("AsyncServerStreamingCall::process_start KO") {
        FakeServerStreamingCall call{&queue, stub_ptr.get()};
        CHECK(!call.finish_called());
        CHECK_NOTHROW(call.trigger_start(false));
        CHECK(call.finish_called());
    }

    SECTION("AsyncServerStreamingCall::handle_read") {
        FakeServerStreamingCall call{&queue, stub_ptr.get()};
        CHECK(!call.read_completed());
        CHECK_NOTHROW(call.trigger_read(true));
        CHECK(call.read_completed());
    }

    SECTION("AsyncServerStreamingCall::handle_finish") {
        FakeServerStreamingCall call{&queue, stub_ptr.get()};
        CHECK(!call.finished());
        CHECK_NOTHROW(call.trigger_finish(true));
        CHECK(call.finished());
    }

    SECTION("print ServerStreamingStats") {
        CHECK_NOTHROW(null_stream() <<  FakeServerStreamingCall::stats());
    }
}

#endif // SILKWORM_SANITIZE

} // namespace silkworm::rpc
