// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "net_api.hpp"

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
