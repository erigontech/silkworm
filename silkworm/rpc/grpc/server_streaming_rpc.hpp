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

#pragma once

#include <memory>
#include <system_error>
#include <utility>

#include <agrpc/rpc.hpp>
#include <boost/asio/compose.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/append.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/grpc/dispatcher.hpp>
#include <silkworm/rpc/grpc/error.hpp>
#include <silkworm/rpc/grpc/util.hpp>

namespace silkworm {

namespace detail {
    struct RequestTag {
    };

    struct ReadTag {
    };
}  // namespace detail

template <auto Rpc>
class ServerStreamingRpc;

template <
    typename Stub,
    typename Request,
    template <typename> typename Responder,
    typename Reply,
    std::unique_ptr<Responder<Reply>> (Stub::*PrepareAsync)(grpc::ClientContext*, const Request&, grpc::CompletionQueue*)>
class ServerStreamingRpc<PrepareAsync> {
  private:
    template <typename Dispatcher>
    struct StartRequest {
        ServerStreamingRpc& self_;
        const Request& request;
        [[no_unique_address]] Dispatcher dispatcher_;

        template <typename Op>
        void operator()(Op& op) {
            SILK_TRACE << "ServerStreamingRpc::StartRequest::initiate r=" << self_.reader_.get() << " START";
            agrpc::request(PrepareAsync, self_.stub_, self_.context_, request, self_.reader_,
                           boost::asio::bind_executor(self_.grpc_context_, std::move(op)));
            SILK_TRACE << "ServerStreamingRpc::StartRequest::initiate r=" << self_.reader_.get() << " END";
        }

        template <typename Op>
        void operator()(Op& op, bool ok) {
            dispatcher_.dispatch(std::move(op), ok, detail::RequestTag{});
        }

        template <typename Op>
        void operator()(Op& op, bool ok, detail::RequestTag) {
            if (ok) {
                SILK_TRACE << "ServerStreamingRpc::StartRequest(op, ok): self_.reader_=" << self_.reader_.get() << " START";
                op.complete({});
                SILK_TRACE << "ServerStreamingRpc::StartRequest(op, ok): self_.reader_=" << self_.reader_.get() << " END";
            } else {
                self_.finish(std::move(op));
            }
        }

        template <typename Op>
        void operator()(Op& op, const boost::system::error_code& ec) {
            SILK_TRACE << "ServerStreamingRpc::StartRequest(op, ec): self_.reader_=" << self_.reader_.get() << " ec=" << ec;
            op.complete(ec);
        }
    };

    template <typename Dispatcher>
    struct Read {
        ServerStreamingRpc& self_;
        [[no_unique_address]] Dispatcher dispatcher_;

        template <typename Op>
        void operator()(Op& op) {
            SILK_TRACE << "ServerStreamingRpc::Read::initiate r=" << self_.reader_.get() << " START";
            agrpc::read(self_.reader_, self_.reply_, boost::asio::bind_executor(self_.grpc_context_, std::move(op)));
            SILK_TRACE << "ServerStreamingRpc::Read::initiate r=" << self_.reader_.get() << " END";
        }

        template <typename Op>
        void operator()(Op& op, bool ok) {
            dispatcher_.dispatch(std::move(op), ok, detail::ReadTag{});
        }

        template <typename Op>
        void operator()(Op& op, bool ok, detail::ReadTag) {
            SILK_TRACE << "ServerStreamingRpc::Read::completed r=" << self_.reader_.get() << " ok=" << ok;
            if (ok) {
                op.complete({}, std::move(self_.reply_));
            } else {
                // Remember that a failure occurred in read
                self_.read_failed_ = true;
                self_.finish(std::move(op));
            }
        }

        template <typename Op>
        void operator()(Op& op, const boost::system::error_code& ec) {
            SILK_TRACE << "ServerStreamingRpc::Read::error r=" << self_.reader_.get() << " ec=" << ec;
            op.complete(ec, {});
        }
    };

    struct Finish {
        ServerStreamingRpc& self_;

        template <typename Op>
        void operator()(Op& op) {
            SILK_TRACE << "ServerStreamingRpc::Finish::initiate " << this << " START";
            agrpc::finish(self_.reader_, self_.status_, boost::asio::bind_executor(self_.grpc_context_, std::move(op)));
            SILK_TRACE << "ServerStreamingRpc::Finish::initiate " << this << " END";
        }

        template <typename Op>
        void operator()(Op& op, bool ok) {
            // Check Finish result to treat any unknown error as such (strict)
            if (!ok) {
                self_.status_ = grpc::Status{grpc::StatusCode::UNKNOWN, "unknown error in finish"};
            }
            // Check OK status AND read failure to treat graceful close on server-side as operation aborted. Otherwise the user should
            // try to detect such condition by filtering on "empty" (default-constructed) reply, which is not necessarily invalid.
            // It is legit using gRPC codes for application-level errors: https://grpc.github.io/grpc/core/md_doc_statuscodes.html
            if (self_.status_.ok() && self_.read_failed_) {
                self_.status_ = grpc::Status{grpc::StatusCode::ABORTED, "operation closed by server"};
            }

            SILK_DEBUG << "ServerStreamingRpc::Finish::completed ok=" << ok << " " << self_.status_;
            if (self_.status_.ok()) {
                op.complete({});
            } else {
                op.complete(make_error_code(self_.status_.error_code(), self_.status_.error_message()));
            }
        }
    };

  public:
    explicit ServerStreamingRpc(Stub& stub, agrpc::GrpcContext& grpc_context)
        : stub_(stub), grpc_context_(grpc_context), read_failed_{false} {
    }

    template <typename CompletionToken = agrpc::DefaultCompletionToken>
    auto request(const Request& request, CompletionToken&& token = {}) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
            StartRequest<detail::InlineDispatcher>{*this, request}, token);
    }

    template <typename Executor, typename CompletionToken = agrpc::DefaultCompletionToken>
    auto request_on(const Executor& executor, const Request& request, CompletionToken&& token = {}) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(
            StartRequest<detail::ExecutorDispatcher<Executor>>{*this, request, {executor}}, token);
    }

    template <typename CompletionToken = agrpc::DefaultCompletionToken>
    auto read(CompletionToken&& token = {}) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, Reply)>(
            Read<detail::InlineDispatcher>{*this}, token);
    }

    template <typename Executor, typename CompletionToken = agrpc::DefaultCompletionToken>
    auto read_on(const Executor& executor, CompletionToken&& token = {}) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code, Reply)>(
            Read<detail::ExecutorDispatcher<Executor>>{*this, {executor}}, token);
    }

    void cancel() {
        SILK_TRACE << "ServerStreamingRpc::cancel START";
        context_.TryCancel();
        SILK_TRACE << "ServerStreamingRpc::cancel END";
    }

  private:
    template <typename CompletionToken = agrpc::DefaultCompletionToken>
    auto finish(CompletionToken&& token = {}) {
        return boost::asio::async_compose<CompletionToken, void(boost::system::error_code)>(Finish{*this}, token);
    }

    Stub& stub_;
    agrpc::GrpcContext& grpc_context_;
    grpc::ClientContext context_;
    std::unique_ptr<Responder<Reply>> reader_;
    Reply reply_;
    grpc::Status status_;
    bool read_failed_;
};

}  // namespace silkworm
