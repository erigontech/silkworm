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

#include <sstream>

namespace silkworm {

EthereumBackEnd::EthereumBackEnd(const NodeSettings& node_settings, mdbx::env* chaindata_env)
    : EthereumBackEnd(node_settings, chaindata_env, std::make_unique<StateChangeCollection>()) {
}

EthereumBackEnd::EthereumBackEnd(
    const NodeSettings& node_settings,
    mdbx::env* chaindata_env,
    std::unique_ptr<StateChangeCollection> state_change_collection)
    : node_settings_(node_settings),
      chaindata_env_(chaindata_env),
      state_change_collection_(std::move(state_change_collection)) {
    // Get the numeric chain identifier from node settings
    if (node_settings_.chain_config) {
        chain_id_ = (*node_settings_.chain_config).chain_id;
    }

    // Get the list of Sentry client addresses from node settings
    std::stringstream sentry_list_stream{node_settings_.external_sentry_addr};
    std::string sentry_address;
    while (std::getline(sentry_list_stream, sentry_address, kSentryAddressDelimiter)) {
        sentry_addresses_.push_back(sentry_address);
    }
}

void EthereumBackEnd::set_node_name(const std::string& node_name) noexcept {
    node_name_ = node_name;
}

void EthereumBackEnd::close() {
    state_change_collection_->close();
}

}  // namespace silkworm
