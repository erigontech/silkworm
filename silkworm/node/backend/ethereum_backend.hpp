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
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/node/backend/state_change_collection.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/sentry/api/common/sentry_client.hpp>

namespace silkworm {

constexpr const char* kDefaultNodeName{"silkworm"};

class EthereumBackEnd {
  public:
    explicit EthereumBackEnd(
        const NodeSettings& node_settings,
        mdbx::env* chaindata_env,
        std::shared_ptr<sentry::api::SentryClient> sentry_client);
    ~EthereumBackEnd();

    EthereumBackEnd(const EthereumBackEnd&) = delete;
    EthereumBackEnd& operator=(const EthereumBackEnd&) = delete;

    [[nodiscard]] mdbx::env* chaindata_env() const noexcept { return chaindata_env_; }
    [[nodiscard]] const std::string& node_name() const noexcept { return node_name_; }
    [[nodiscard]] std::optional<uint64_t> chain_id() const noexcept { return chain_id_; }
    [[nodiscard]] std::optional<evmc::address> etherbase() const noexcept { return node_settings_.etherbase; }
    [[nodiscard]] std::shared_ptr<sentry::api::SentryClient> sentry_client() const noexcept { return sentry_client_; }
    [[nodiscard]] StateChangeCollection* state_change_source() const noexcept { return state_change_collection_.get(); }

    void set_node_name(const std::string& node_name) noexcept;

    void close();

  protected:
    //! Constructor for testability
    EthereumBackEnd(
        const NodeSettings& node_settings,
        mdbx::env* chaindata_env,
        std::shared_ptr<sentry::api::SentryClient> sentry_client,
        std::unique_ptr<StateChangeCollection> state_change_collection);

  private:
    const NodeSettings& node_settings_;
    mdbx::env* chaindata_env_;
    std::string node_name_{kDefaultNodeName};
    std::optional<uint64_t> chain_id_{std::nullopt};
    std::shared_ptr<sentry::api::SentryClient> sentry_client_;
    std::unique_ptr<StateChangeCollection> state_change_collection_;
};

}  // namespace silkworm
