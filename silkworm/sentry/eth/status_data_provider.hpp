// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    StatusData get_status_data(uint8_t eth_version) const;

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
