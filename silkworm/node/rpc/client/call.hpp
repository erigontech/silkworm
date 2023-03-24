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

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <agrpc/detail/rpc.hpp>
#include <agrpc/grpc_context.hpp>
#include <agrpc/rpc.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/node/common/log.hpp>

namespace silkworm::rpc {

class GrpcStatusError : public std::runtime_error {
  public:
    explicit GrpcStatusError(grpc::Status status)
        : std::runtime_error(status.error_message()),
          status_(std::move(status)) {}

    [[nodiscard]] const grpc::Status& status() const { return status_; }

  private:
    grpc::Status status_;
};

template <class Stub, class Request, class Response>
boost::asio::awaitable<Response> unary_rpc(
    agrpc::detail::ClientUnaryRequest<Stub, Request, grpc::ClientAsyncResponseReader<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context) {
    grpc::ClientContext client_context;
    client_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

    std::unique_ptr<grpc::ClientAsyncResponseReader<Response>> reader =
        agrpc::request(rpc, stub, client_context, request, grpc_context);

    Response reply;
    grpc::Status status;
    co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));

    if (!status.ok()) {
        throw GrpcStatusError(std::move(status));
    }

    co_return reply;
}

template <class Stub, class Request, class Response>
boost::asio::awaitable<void> streaming_rpc(
    agrpc::detail::PrepareAsyncClientServerStreamingRequest<Stub, Request, grpc::ClientAsyncReader<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    std::function<boost::asio::awaitable<void>(Response)> consumer) {
    grpc::ClientContext client_context;
    client_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

    std::unique_ptr<grpc::ClientAsyncReader<Response>> reader;
    bool ok = co_await agrpc::request(
        rpc,
        stub,
        client_context,
        std::move(request),
        reader,
        boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));

    while (ok) {
        Response response;
        ok = co_await agrpc::read(reader, response, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
        if (ok) {
            co_await consumer(std::move(response));
        }
    }

    grpc::Status status;
    co_await agrpc::finish(reader, status, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));

    if (!status.ok()) {
        throw GrpcStatusError(std::move(status));
    }
}

namespace detail {
    bool is_disconnect_error(const GrpcStatusError& ex, grpc::Channel& channel);
    boost::asio::awaitable<void> reconnect_channel(grpc::Channel& channel);
}  // namespace detail

template <class Stub, class Request, class Response>
boost::asio::awaitable<Response> unary_rpc_with_retries(
    agrpc::detail::ClientUnaryRequest<Stub, Request, grpc::ClientAsyncResponseReader<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    grpc::Channel& channel) {
    // loop until a successful return or cancellation
    while (true) {
        try {
            co_return (co_await unary_rpc(rpc, stub, request, grpc_context));
        } catch (const GrpcStatusError& ex) {
            if (detail::is_disconnect_error(ex, channel)) {
                log::Warning() << "GRPC call failed: " << ex.what();
            } else {
                throw;
            }
        }

        co_await detail::reconnect_channel(channel);
    }
}

template <class Stub, class Request, class Response>
boost::asio::awaitable<void> streaming_rpc_with_retries(
    agrpc::detail::PrepareAsyncClientServerStreamingRequest<Stub, Request, grpc::ClientAsyncReader<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    grpc::Channel& channel,
    std::function<boost::asio::awaitable<void>(Response)> consumer) {
    // loop until a successful return or cancellation
    while (true) {
        try {
            co_await streaming_rpc(rpc, stub, request, grpc_context, consumer);
            break;
        } catch (const GrpcStatusError& ex) {
            if (detail::is_disconnect_error(ex, channel)) {
                log::Warning() << "GRPC streaming call failed: " << ex.what();
            } else {
                throw;
            }
        }

        co_await detail::reconnect_channel(channel);
    }
}

}  // namespace silkworm::rpc
