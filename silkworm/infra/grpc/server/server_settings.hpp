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
