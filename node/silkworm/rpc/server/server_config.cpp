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

#include "server_config.hpp"

namespace silkworm::rpc {

ServerConfig::ServerConfig(std::shared_ptr<grpc::ServerCredentials> credentials)
    : address_uri_{kDefaultAddressUri},
      credentials_(credentials),
      num_contexts_{kDefaultNumContexts},
      wait_mode_{WaitMode::blocking} {
}

void ServerConfig::set_address_uri(const std::string& address_uri) noexcept {
    address_uri_ = address_uri;
}

void ServerConfig::set_credentials(std::shared_ptr<grpc::ServerCredentials> credentials) noexcept {
    credentials_ = credentials;
}

void ServerConfig::set_num_contexts(uint32_t num_contexts) noexcept {
    num_contexts_ = num_contexts;
}

void ServerConfig::set_wait_mode(WaitMode wait_mode) noexcept {
    wait_mode_ = wait_mode;
}

}  // namespace silkworm::rpc
