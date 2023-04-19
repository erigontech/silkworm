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

constexpr const char* kDefaultAddressUri{"localhost:9090"};

class ServerConfig {
  public:
    explicit ServerConfig(std::shared_ptr<grpc::ServerCredentials> credentials = grpc::InsecureServerCredentials());
    virtual ~ServerConfig() = default;

    void set_address_uri(const std::string& address_uri) noexcept;
    void set_credentials(std::shared_ptr<grpc::ServerCredentials> credentials) noexcept;
    void set_context_pool_settings(concurrency::ContextPoolSettings settings) noexcept;

    [[nodiscard]] const std::string& address_uri() const noexcept { return address_uri_; }  // TODO(canepat) remove as duplicated
    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials> credentials() const noexcept { return credentials_; }
    [[nodiscard]] const concurrency::ContextPoolSettings& context_pool_settings() const noexcept { return context_pool_settings_; }

  private:
    std::string address_uri_;
    std::shared_ptr<grpc::ServerCredentials> credentials_;
    concurrency::ContextPoolSettings context_pool_settings_;
};

}  // namespace silkworm::rpc
