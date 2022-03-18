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

#include <silkworm/common/base.hpp>
#include <silkworm/chain/config.hpp>

namespace silkworm {

constexpr const char* kDefaultNodeName{"silkworm"};

class EthereumBackEnd {
  public:
    explicit EthereumBackEnd(const ChainConfig& chain_config = kMainnetConfig);

    EthereumBackEnd(const EthereumBackEnd&) = delete;
    EthereumBackEnd& operator=(const EthereumBackEnd&) = delete;

    const std::string& node_name() const noexcept { return node_name_; }
    uint64_t chain_id() const noexcept { return chain_config_.chain_id; }
    std::optional<evmc::address> etherbase() const noexcept { return etherbase_; }

    void set_node_name(const std::string& node_name) noexcept;
    void set_etherbase(const evmc::address& etherbase) noexcept;

  private:
    const ChainConfig& chain_config_;
    std::string node_name_{kDefaultNodeName};
    std::optional<evmc::address> etherbase_{std::nullopt};
};

} // namespace silkworm

#endif // SILKWORM_BACKEND_ETHEREUM_BACKEND_HPP_
