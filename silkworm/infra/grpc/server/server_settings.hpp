// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::rpc {

inline constexpr const char* kDefaultAddressUri{"localhost:9090"};

//! Configuration settings for private (i.e. internal) API gRPC server
struct ServerSettings {
    //! gRPC private API bind address (IP:port)
    std::string address_uri{kDefaultAddressUri};
    //! gRPC private API credentials
    std::shared_ptr<grpc::ServerCredentials> credentials{grpc::InsecureServerCredentials()};
    //! Configuration for gRPC server execution pool
    concurrency::ContextPoolSettings context_pool_settings;
};

}  // namespace silkworm::rpc
