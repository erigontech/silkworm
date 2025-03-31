// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <ostream>

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/kv_mock_fix24351.grpc.pb.h>
#include <silkworm/infra/grpc/test_util/test_runner.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/interfaces/remote/kv.grpc.pb.h>

namespace silkworm::rpc {

using testing::Return;
using namespace silkworm::grpc::test_util;
namespace proto = ::remote;

class CallTest : public silkworm::test_util::ContextTestBase {
  public:
    //! Check that before *and* after calling unary_rpc utility function we're executing on the same asio::io_context thread.
    //! This is a widespread threading assumption for our production code (e.g. rpcdaemon) but needs special handling because
    //! asio-grpc library functions currently used in unary_rpc do complete handlers on GrpcContext service thread
    template <class Stub, class Request, class Response>
    Task<Response> check_unary_grpc_threading(
        agrpc::detail::ClientUnaryRequest<Stub, Request, ::grpc::ClientAsyncResponseReaderInterface<Response>> rpc,
        std::unique_ptr<Stub>& stub,
        Request request,
        agrpc::GrpcContext& grpc_context) {
        const auto this_thread_id{std::this_thread::get_id()};
        CHECK(ioc_.get_executor().running_in_this_thread());
        const auto response = co_await unary_rpc(rpc, *stub, request, grpc_context);
        CHECK(ioc_.get_executor().running_in_this_thread());
        CHECK(this_thread_id == std::this_thread::get_id());
        co_return response;
    }

    //! Same check as above but for agrpc::ClientRPC<>::request, which does not require dispatching to asio::io_context executor
    //! because it does guarantee to complete handlers on the calling executor: https://github.com/erigontech/silkrpc/issues/439
    Task<::types::VersionReply> check_unary_agrpc_client_threading(
        proto::KV::StubInterface& stub,
        google::protobuf::Empty request,
        agrpc::GrpcContext& grpc_context) {
        ::grpc::ClientContext client_context;
        client_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

        using RPC = boost::asio::use_awaitable_t<>::as_default_on_t<agrpc::ClientRPC<&proto::KV::StubInterface::PrepareAsyncVersion>>;

        RPC::Response response;
        const auto this_thread_id{std::this_thread::get_id()};
        CHECK(ioc_.get_executor().running_in_this_thread());
        ::grpc::Status status = co_await RPC::request(grpc_context, stub, client_context, request, response);
        CHECK(ioc_.get_executor().running_in_this_thread());
        CHECK(this_thread_id == std::this_thread::get_id());

        if (!status.ok()) {
            throw GrpcStatusError(std::move(status));
        }

        co_return response;
    }

    using StrictMockKVStub = testing::StrictMock<proto::MockKVStub>;
    using StrictMockKVVersionAsyncResponseReader = rpc::test::StrictMockAsyncResponseReader<::types::VersionReply>;

  protected:
    //! Mocked stub of gRPC KV interface
    std::unique_ptr<StrictMockKVStub> stub_{std::make_unique<StrictMockKVStub>()};

    //! Mocked reader for Version unary RPC of gRPC KV interface
    std::unique_ptr<StrictMockKVVersionAsyncResponseReader> version_reader_ptr_{
        std::make_unique<StrictMockKVVersionAsyncResponseReader>()};
    StrictMockKVVersionAsyncResponseReader& version_reader_{*version_reader_ptr_};
};

TEST_CASE_METHOD(CallTest, "Unary gRPC threading: unary_rpc", "[grpc][client]") {
    // Set the call expectations:
    // 1. remote::KV::StubInterface::AsyncVersionRaw call succeeds
    EXPECT_CALL(*stub_, AsyncVersionRaw).WillOnce(Return(version_reader_ptr_.get()));
    // 2. AsyncResponseReader<types::VersionReply>::Finish call succeeds w/ status OK
    EXPECT_CALL(version_reader_, Finish).WillOnce(test::finish_ok(grpc_context_));

    // Trick necessary because expectations require MockKVStub, whilst production code wants remote::KV::StubInterface
    std::unique_ptr<proto::KV::StubInterface> stub{std::move(stub_)};

    // Execute the test: check threading assumptions during async Version RPC execution
    spawn_and_wait(check_unary_grpc_threading(&proto::KV::StubInterface::AsyncVersion, stub, google::protobuf::Empty{}, grpc_context_));
}

TEST_CASE_METHOD(CallTest, "Unary gRPC threading: agrpc::ClientRPC", "[grpc][client]") {
    // Set the call expectations:
    // 1. remote::KV::StubInterface::PrepareAsyncVersionRaw call succeeds
    EXPECT_CALL(*stub_, PrepareAsyncVersionRaw).WillOnce(Return(version_reader_ptr_.get()));
    // 2. AsyncResponseReader<types::VersionReply>::StartCall call succeeds
    EXPECT_CALL(version_reader_, StartCall).WillOnce([&]() {});
    // 3. AsyncResponseReader<types::VersionReply>::Finish call succeeds w/ status OK
    EXPECT_CALL(version_reader_, Finish).WillOnce(test::finish_ok(grpc_context_));

    // Execute the test: check threading assumptions during async Version RPC execution
    spawn_and_wait(check_unary_agrpc_client_threading(*stub_, google::protobuf::Empty{}, grpc_context_));
}

TEST_CASE_METHOD(CallTest, "Unary gRPC cancelling: unary_rpc", "[grpc][client]") {
    // Set the call expectations:
    // 1. remote::KV::StubInterface::AsyncVersionRaw call succeeds
    EXPECT_CALL(*stub_, AsyncVersionRaw).WillOnce(Return(version_reader_ptr_.get()));
    // 2. AsyncResponseReader<types::VersionReply>::Finish call fails w/ status CANCELLED
    boost::asio::cancellation_signal cancellation_signal;
    auto cancellation_slot = cancellation_signal.slot();

    // Trick: we use Finish as a hook to signal cancellation, but then we must trigger tag by hand anyway
    // Better solution possible with agrpc::ClientRPC: use StartCall as a hook to signal cancellation
    EXPECT_CALL(version_reader_, Finish).WillOnce([&](auto&&, ::grpc::Status* status, void* tag) {
        cancellation_signal.emit(boost::asio::cancellation_type::all);
        *status = ::grpc::Status::CANCELLED;
        agrpc::process_grpc_tag(grpc_context_, tag, /*ok=*/true);
    });

    // Trick necessary because expectations require MockKVStub, whilst production code wants remote::KV::StubInterface
    std::unique_ptr<proto::KV::StubInterface> stub{std::move(stub_)};

    // Execute the test: start and then cancel async Version RPC execution
    auto version_reply = spawn(unary_rpc(&proto::KV::StubInterface::AsyncVersion,
                                         *stub,
                                         google::protobuf::Empty{},
                                         grpc_context_,
                                         &cancellation_slot));
    CHECK_THROWS_AS(version_reply.get(), GrpcStatusError);
}

}  // namespace silkworm::rpc
