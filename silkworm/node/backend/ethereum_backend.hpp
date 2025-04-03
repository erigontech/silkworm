// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>

#include <silkworm/db/kv/grpc/server/state_change_collection.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm {

inline constexpr const char* kDefaultNodeName{"silkworm"};

class EthereumBackEnd {
  public:
    explicit EthereumBackEnd(
        const NodeSettings& node_settings,
        datastore::kvdb::ROAccess chaindata,
        std::shared_ptr<sentry::api::SentryClient> sentry_client);
    ~EthereumBackEnd();

    EthereumBackEnd(const EthereumBackEnd&) = delete;
    EthereumBackEnd& operator=(const EthereumBackEnd&) = delete;

    datastore::kvdb::ROAccess chaindata() const noexcept { return chaindata_; }
    const std::string& node_name() const noexcept { return node_name_; }
    std::optional<uint64_t> chain_id() const noexcept { return chain_id_; }
    std::optional<evmc::address> etherbase() const noexcept { return node_settings_.etherbase; }
    std::shared_ptr<sentry::api::SentryClient> sentry_client() const noexcept { return sentry_client_; }
    StateChangeCollection* state_change_source() const noexcept { return state_change_collection_.get(); }

    void set_node_name(const std::string& node_name) noexcept;

    void close();

  protected:
    //! Constructor for testability
    EthereumBackEnd(
        const NodeSettings& node_settings,
        datastore::kvdb::ROAccess chaindata,
        std::shared_ptr<sentry::api::SentryClient> sentry_client,
        std::unique_ptr<StateChangeCollection> state_change_collection);

  private:
    const NodeSettings& node_settings_;
    datastore::kvdb::ROAccess chaindata_;
    std::string node_name_{kDefaultNodeName};
    std::optional<uint64_t> chain_id_{std::nullopt};
    std::shared_ptr<sentry::api::SentryClient> sentry_client_;
    std::unique_ptr<StateChangeCollection> state_change_collection_;
};

}  // namespace silkworm
