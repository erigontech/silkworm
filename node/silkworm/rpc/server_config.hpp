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

#ifndef SILKWORM_RPC_SERVER_CONFIG_HPP_
#define SILKWORM_RPC_SERVER_CONFIG_HPP_

#include <memory>
#include <string>
#include <thread>

#include <grpcpp/grpcpp.h>

namespace silkworm::rpc {

constexpr const char* kDefaultNodeName{"silkworm"};
constexpr const char* kDefaultAddressUri{"localhost:9090"};
const std::shared_ptr<grpc::ServerCredentials> kDefaultServerCredentials{grpc::InsecureServerCredentials()};
const uint32_t kDefaultNumContexts{std::thread::hardware_concurrency()};

class ServerConfig {
  public:
    ServerConfig();
    virtual ~ServerConfig() {}

    void set_node_name(const std::string& node_name) noexcept;
    void set_address_uri(const std::string& address_uri) noexcept;
    void set_credentials(std::shared_ptr<grpc::ServerCredentials> credentials) noexcept;
    void set_num_contexts(uint32_t num_contexts) noexcept;

    const std::string& node_name() const noexcept { return node_name_; }
    const std::string& address_uri() const noexcept { return address_uri_; }
    std::shared_ptr<grpc::ServerCredentials> credentials() const noexcept { return credentials_; }
    uint32_t num_contexts() const noexcept { return num_contexts_; }

  private:
    std::string node_name_;
    std::string address_uri_;
    std::shared_ptr<grpc::ServerCredentials> credentials_;
    uint32_t num_contexts_;
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVER_CONFIG_HPP_
