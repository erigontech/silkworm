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
#include <thread>

#include <grpcpp/grpcpp.h>

#include <silkworm/rpc/server/wait_strategy.hpp>

namespace silkworm::rpc {

constexpr const char* kDefaultAddressUri{"localhost:9090"};
const uint32_t kDefaultNumContexts{std::thread::hardware_concurrency()};

class ServerConfig {
  public:
    ServerConfig(std::shared_ptr<grpc::ServerCredentials> credentials = grpc::InsecureServerCredentials());
    virtual ~ServerConfig() {}

    void set_address_uri(const std::string& address_uri) noexcept;
    void set_credentials(std::shared_ptr<grpc::ServerCredentials> credentials) noexcept;
    void set_num_contexts(uint32_t num_contexts) noexcept;
    void set_wait_mode(WaitMode wait_mode) noexcept;

    const std::string& address_uri() const noexcept { return address_uri_; }  // TODO(canepat) remove as duplicated
    std::shared_ptr<grpc::ServerCredentials> credentials() const noexcept { return credentials_; }
    uint32_t num_contexts() const noexcept { return num_contexts_; }
    WaitMode wait_mode() const noexcept { return wait_mode_; }

  private:
    std::string address_uri_;
    std::shared_ptr<grpc::ServerCredentials> credentials_;
    uint32_t num_contexts_;

    //! The waiting mode used by execution loops during idle cycles.
    WaitMode wait_mode_;
};

}  // namespace silkworm::rpc
