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

#include <utility>  // for std::exchange in Boost 1.78, fixed in Boost 1.79

#include <agrpc/detail/rpc.hpp>
#include <agrpc/grpc_context.hpp>
#include <agrpc/rpc.hpp>

namespace silkworm::rpc {

template <class Stub, class DerivedStub, class Request, class Response, class Responder>
boost::asio::awaitable<grpc::Status> unary_rpc(agrpc::detail::ClientUnaryRequest<Stub, Request, Responder> rpc, DerivedStub& stub,
                                               const Request& request, Response& reply, agrpc::GrpcContext& grpc_context) {
    grpc::ClientContext client_context;
    std::unique_ptr<grpc::ClientAsyncResponseReader<Response>> reader = agrpc::request(rpc, stub, client_context, request, grpc_context);

    grpc::Status status;
    bool finish_ok = co_await agrpc::finish(reader, reply, status, boost::asio::bind_executor(grpc_context, boost::asio::use_awaitable));
    if (!finish_ok) {
        throw std::runtime_error{"unary RPC failed"};
    }
    co_return status;
}

}  // namespace silkworm::rpc
