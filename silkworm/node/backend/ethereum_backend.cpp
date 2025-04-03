// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ethereum_backend.hpp"

namespace silkworm {

EthereumBackEnd::EthereumBackEnd(
    const NodeSettings& node_settings,
    datastore::kvdb::ROAccess chaindata,
    std::shared_ptr<sentry::api::SentryClient> sentry_client)
    : EthereumBackEnd{
          node_settings,
          std::move(chaindata),
          std::move(sentry_client),
          std::make_unique<StateChangeCollection>(),
      } {
}

EthereumBackEnd::EthereumBackEnd(
    const NodeSettings& node_settings,
    datastore::kvdb::ROAccess chaindata,
    std::shared_ptr<sentry::api::SentryClient> sentry_client,
    std::unique_ptr<StateChangeCollection> state_change_collection)
    : node_settings_(node_settings),
      chaindata_(std::move(chaindata)),
      sentry_client_(std::move(sentry_client)),
      state_change_collection_(std::move(state_change_collection)) {
    // Get the numeric chain identifier from node settings
    if (node_settings_.chain_config) {
        chain_id_ = (*node_settings_.chain_config).chain_id;
    }
}

EthereumBackEnd::~EthereumBackEnd() {
    close();
}

void EthereumBackEnd::set_node_name(const std::string& node_name) noexcept {
    node_name_ = node_name;
}

void EthereumBackEnd::close() {
    state_change_collection_->close();
}

}  // namespace silkworm
