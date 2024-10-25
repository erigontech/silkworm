/*
   Copyright 2023 The Silkworm Authors

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

#include <functional>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/types/chain_head.hpp>

#include "status_data.hpp"

namespace silkworm::sentry::eth {

class StatusDataProvider {
  public:
    StatusDataProvider(
        std::function<ChainHead()> chain_head_provider,
        const ChainConfig& chain_config)
        : chain_head_provider_(std::move(chain_head_provider)),
          chain_config_(chain_config) {}

    using StatusData = silkworm::sentry::eth::StatusData;
    StatusData get_status_data(uint8_t eth_version);

    using StatusDataProviderFactory = std::function<Task<StatusData>(uint8_t eth_version)>;
    static StatusDataProviderFactory to_factory_function(StatusDataProvider provider);

  private:
    static StatusData make_status_data(
        ChainHead chain_head,
        uint8_t eth_version,
        const ChainConfig& chain_config);

    std::function<ChainHead()> chain_head_provider_;
    const ChainConfig& chain_config_;
};

}  // namespace silkworm::sentry::eth
