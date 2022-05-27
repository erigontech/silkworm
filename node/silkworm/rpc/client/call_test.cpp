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

#include <catch2/catch.hpp>

#include <remote/ethbackend.grpc.pb.h>

namespace silkworm::rpc {

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
      protected:
        void handle_finish(bool /*ok*/) override {}
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
}
#endif // SILKWORM_SANITIZE

} // namespace silkworm::rpc
