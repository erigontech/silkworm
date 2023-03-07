/*
   Copyright 2021 The Silkrpc Authors

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

#include "net_api.hpp"

#include <agrpc/grpc_context.hpp>
#include <agrpc/test.hpp>
#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/ethbackend/remote_backend.hpp>

namespace silkrpc::commands {

using Catch::Matchers::Message;

TEST_CASE("NetRpcApi::NetRpcApi", "[silkrpc][erigon_api]") {
    boost::asio::io_context io_context;
    auto channel{grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials())};
    agrpc::GrpcContext grpc_context{std::make_unique<grpc::CompletionQueue>()};
    std::unique_ptr<ethbackend::BackEnd> backend{
        std::make_unique<ethbackend::RemoteBackEnd>(io_context, channel, grpc_context)
    };
    CHECK_NOTHROW(NetRpcApi{backend});
}

} // namespace silkrpc::commands
