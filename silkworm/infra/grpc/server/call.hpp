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

#include <atomic>
#include <functional>
#include <list>
#include <stdexcept>
#include <utility>

#include <agrpc/repeatedly_request.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <grpcpp/grpcpp.h>
#include <grpcpp/impl/codegen/async_stream.h>
#include <grpcpp/impl/codegen/async_unary_call.h>
#include <magic_enum.hpp>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

//! Register a server-side RPC repeatedly: whenever a client request is accepted, another waiting RPC is started
template <class RPC, class AsyncService, class RequestHandler>
void request_repeatedly(agrpc::GrpcContext& grpc_context, const AsyncService& service, RPC rpc, RequestHandler&& handler) {
    agrpc::repeatedly_request(rpc, *service, boost::asio::bind_executor(grpc_context, handler));
}

namespace server {

    //! The max idle interval to protect from clients which don't send any requests.
    constexpr std::chrono::milliseconds kDefaultMaxIdleDuration{30'000};

    //! This represents the server-side base gRPC call.
    class Call {
      public:
        //! Returns the number of outstanding RPC instances.
        static int64_t instance_count() { return instance_count_; }

        //! Returns the number of total RPC instances.
        static uint64_t total_count() { return total_count_; }

        explicit Call(grpc::ServerContext& server_context) : server_context_(server_context) {
            ++instance_count_;
            ++total_count_;
            SILK_TRACE << "Call::Call [" << this << "] instances: " << instance_count() << " total: " << total_count();
        }

        ~Call() {
            --instance_count_;
            SILK_TRACE << "Call::~Call [" << this << "] instances: " << instance_count() << " total: " << total_count();
        }

        //! Returns a unique identifier of the RPC client for this call.
        [[nodiscard]] std::string peer() const { return server_context_.peer(); }

      protected:
        //! Used to access the options and current status of the RPC.
        grpc::ServerContext& server_context_;

      private:
        //! Keep track of the total outstanding RPC calls (intentionally signed to spot underflow).
        inline static std::atomic_int64_t instance_count_ = 0;

        //! Keep track of the total RPC calls.
        inline static std::atomic_uint64_t total_count_ = 0;
    };

    //! This represents any unary RPC (i.e. one-client-request, one-server-response).
    template <class Request, class Response>
    class UnaryCall : public Call {
      public:
        using Base = UnaryCall<Request, Response>;
        using Responder = grpc::ServerAsyncResponseWriter<Response>;

        UnaryCall(grpc::ServerContext& server_context, Request& request, Responder& responder)
            : Call(server_context), request_(request), responder_(responder) {}

      protected:
        Request& request_;
        Responder& responder_;
    };

    //! This represents any server-streaming RPC (i.e. one-client-request, many-server-responses).
    template <class Request, class Response>
    class ServerStreamingCall : public Call {
      public:
        using Base = ServerStreamingCall<Request, Response>;
        using Responder = grpc::ServerAsyncWriter<Response>;

        ServerStreamingCall(grpc::ServerContext& server_context, Request& request, Responder& responder)
            : Call(server_context), request_(request), responder_(responder) {}

      protected:
        Request& request_;
        Responder& responder_;
    };

    //! This represents any bidirectional-streaming RPC (i.e. many-client-requests, many-server-responses).
    template <class Request, class Response>
    class BidiStreamingCall : public Call {
      public:
        using Base = BidiStreamingCall<Request, Response>;
        using Responder = grpc::ServerAsyncReaderWriter<Response, Request>;

        static void set_max_idle_duration(const std::chrono::milliseconds& max_idle_duration) {
            max_idle_duration_ = max_idle_duration;
        }

        BidiStreamingCall(agrpc::GrpcContext& grpc_context, grpc::ServerContext& server_context, Responder& responder)
            : Call(server_context), responder_(responder), grpc_context_(grpc_context) {}

      protected:
        inline static std::chrono::milliseconds max_idle_duration_{kDefaultMaxIdleDuration};

        Responder& responder_;
        agrpc::GrpcContext& grpc_context_;
    };

    class CallException : public std::runtime_error {
      public:
        explicit CallException(grpc::Status&& status)
            : std::runtime_error(status.error_message()), status_(std::move(status)) {}

        [[nodiscard]] grpc::Status status() const { return status_; }

      private:
        grpc::Status status_;
    };

}  // namespace server

}  // namespace silkworm::rpc
