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
#include <string>
#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/detail/rpc.hpp>
#include <agrpc/grpc_context.hpp>
#include <agrpc/rpc.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>

#include "reconnect.hpp"

namespace silkworm::rpc {

class GrpcStatusError : public std::runtime_error {
  public:
    explicit GrpcStatusError(grpc::Status status)
        : std::runtime_error(status.error_message()), status_(std::move(status)) {}

    const grpc::Status& status() const { return status_; }

  private:
    grpc::Status status_;
};

template <class Stub, class Request, class Response>
Task<Response> unary_rpc(
    agrpc::detail::ClientUnaryRequest<Stub, Request, grpc::ClientAsyncResponseReaderInterface<Response>> rpc,
    Stub& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    boost::asio::cancellation_slot* cancellation_slot = nullptr) {
    grpc::ClientContext client_context;
    client_context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(120));
    if (cancellation_slot) {
        cancellation_slot->assign([&client_context](boost::asio::cancellation_type /*type*/) {
            client_context.TryCancel();
        });
    }

    auto task_executor = co_await boost::asio::this_coro::executor;

    std::unique_ptr<grpc::ClientAsyncResponseReaderInterface<Response>> reader =
        agrpc::request(rpc, stub, client_context, request, grpc_context);

    Response reply;
    grpc::Status status;
    co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
    co_await boost::asio::dispatch(boost::asio::bind_executor(task_executor, boost::asio::use_awaitable));

    if (!status.ok()) {
        throw GrpcStatusError(std::move(status));
    }

    co_return reply;
}

template <class Stub, class Request, class Response>
Task<void> server_streaming_rpc(
    agrpc::detail::PrepareAsyncClientServerStreamingRequest<Stub, Request, grpc::ClientAsyncReaderInterface<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    std::function<Task<void>(Response)> consumer,
    boost::asio::cancellation_slot* cancellation_slot = nullptr) {
    grpc::ClientContext client_context;
    if (cancellation_slot) {
        cancellation_slot->assign([&client_context](boost::asio::cancellation_type /*type*/) {
            client_context.TryCancel();
        });
    }

    auto task_executor = co_await boost::asio::this_coro::executor;

    std::unique_ptr<grpc::ClientAsyncReaderInterface<Response>> reader;
    bool ok = co_await agrpc::request(
        rpc,
        stub,
        client_context,
        std::move(request),
        reader,
        boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
    co_await boost::asio::dispatch(boost::asio::bind_executor(task_executor, boost::asio::use_awaitable));

    while (ok) {
        Response response;
        ok = co_await agrpc::read(reader, response, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
        co_await boost::asio::dispatch(boost::asio::bind_executor(task_executor, boost::asio::use_awaitable));
        if (ok) {
            co_await consumer(std::move(response));
        }
    }

    grpc::Status status;
    co_await agrpc::finish(reader, status, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
    co_await boost::asio::dispatch(boost::asio::bind_executor(task_executor, boost::asio::use_awaitable));

    if (!status.ok()) {
        throw GrpcStatusError(std::move(status));
    }
}

using DisconnectHook = std::function<Task<void>()>;

template <class Stub, class Request, class Response>
Task<Response> unary_rpc_with_retries(
    agrpc::detail::ClientUnaryRequest<Stub, Request, grpc::ClientAsyncResponseReaderInterface<Response>> rpc,
    Stub& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    DisconnectHook& on_disconnect,
    grpc::Channel& channel,
    std::string log_prefix,
    int64_t min_msec = kDefaultMinBackoffReconnectTimeout,
    int64_t max_msec = kDefaultMaxBackoffReconnectTimeout) {
    // loop until a successful return or cancellation
    while (true) {
        try {
            co_return (co_await unary_rpc(rpc, stub, request, grpc_context));
        } catch (const GrpcStatusError& ex) {
            if (is_disconnect_error(ex.status(), channel)) {
                SILK_WARN_M(log_prefix) << "GRPC unary call failed: " << ex.what();
            } else {
                throw;
            }
        }

        co_await on_disconnect();
        if (channel.GetState(false) != GRPC_CHANNEL_READY) {
            co_await reconnect_channel(channel, log_prefix, min_msec, max_msec);
        }
    }
}

template <class Stub, class Request, class Response>
Task<void> server_streaming_rpc_with_retries(
    agrpc::detail::PrepareAsyncClientServerStreamingRequest<Stub, Request, grpc::ClientAsyncReaderInterface<Response>> rpc,
    std::unique_ptr<Stub>& stub,
    Request request,
    agrpc::GrpcContext& grpc_context,
    DisconnectHook& on_disconnect,
    grpc::Channel& channel,
    std::string log_prefix,
    std::function<Task<void>(Response)> consumer,
    boost::asio::cancellation_slot* cancellation_signal = nullptr,
    int64_t min_backoff_timeout_msec = kDefaultMinBackoffReconnectTimeout,
    int64_t max_backoff_timeout_msec = kDefaultMaxBackoffReconnectTimeout) {
    // loop until a successful return or cancellation
    while (true) {
        try {
            co_await server_streaming_rpc(rpc, stub, request, grpc_context, consumer, cancellation_signal);
            break;
        } catch (const GrpcStatusError& ex) {
            if (is_disconnect_error(ex.status(), channel)) {
                SILK_WARN_M(log_prefix) << "GRPC server-streaming call failed: " << ex.what();
            } else {
                throw;
            }
        }

        co_await on_disconnect();
        if (channel.GetState(false) != GRPC_CHANNEL_READY) {
            co_await reconnect_channel(channel, log_prefix, min_backoff_timeout_msec, max_backoff_timeout_msec);
        }
    }
}

}  // namespace silkworm::rpc
