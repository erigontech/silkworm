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

#ifndef SILKWORM_BACKEND_ETHEREUM_BACKEND_HPP_
#define SILKWORM_BACKEND_ETHEREUM_BACKEND_HPP_

#include <optional>
#include <string>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/chain/config.hpp>

namespace silkworm {

constexpr const char* kDefaultNodeName{"silkworm"};

class EthereumBackEnd {
  public:
    explicit EthereumBackEnd(const NodeSettings& node_settings, mdbx::env_managed* chaindata_env);

    EthereumBackEnd(const EthereumBackEnd&) = delete;
    EthereumBackEnd& operator=(const EthereumBackEnd&) = delete;

    mdbx::env_managed* chaindata_env() const noexcept { return chaindata_env_; }
    const std::string& node_name() const noexcept { return node_name_; }
    std::optional<uint64_t> chain_id() const noexcept { return chain_id_; }
    std::optional<evmc::address> etherbase() const noexcept { return node_settings_.etherbase; }
    std::vector<std::string> sentry_addresses() const noexcept { return sentry_addresses_; }

    void set_node_name(const std::string& node_name) noexcept;

  private:
    const NodeSettings& node_settings_;
    mdbx::env_managed* chaindata_env_;
    std::string node_name_{kDefaultNodeName};
    std::optional<uint64_t> chain_id_{std::nullopt};
    std::vector<std::string> sentry_addresses_;
};

} // namespace silkworm

#endif // SILKWORM_BACKEND_ETHEREUM_BACKEND_HPP_
