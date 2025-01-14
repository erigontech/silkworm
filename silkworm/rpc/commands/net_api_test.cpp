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

#include "net_api.hpp"

#include <agrpc/test.hpp>
#include <catch2/catch_test_macros.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/rpc/ethbackend/remote_backend.hpp>

namespace silkworm::rpc::commands {

#ifndef SILKWORM_SANITIZE
TEST_CASE("NetRpcApi::NetRpcApi", "[rpc][erigon_api]") {
    boost::asio::io_context ioc;
    auto grpc_channel{grpc::CreateChannel("localhost", grpc::InsecureChannelCredentials())};
    agrpc::GrpcContext grpc_context;
    add_private_service<ethbackend::BackEnd>(
        ioc,
        std::make_unique<ethbackend::RemoteBackEnd>(grpc_channel, grpc_context));
    CHECK_NOTHROW(NetRpcApi{ioc});
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::commands
