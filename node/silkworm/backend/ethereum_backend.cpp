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

#include "ethereum_backend.hpp"

namespace silkworm {

EthereumBackEnd::EthereumBackEnd(const ChainConfig& chain_config) : chain_config_(chain_config) {
}

void EthereumBackEnd::set_node_name(const std::string& node_name) noexcept {
    node_name_ = node_name;
}

void EthereumBackEnd::set_etherbase(const evmc::address& etherbase) noexcept {
    etherbase_ = etherbase;
}

void EthereumBackEnd::add_sentry_address(const std::string& address_uri) noexcept {
    sentry_addresses_.push_back(address_uri);
}

} // namespace silkworm
