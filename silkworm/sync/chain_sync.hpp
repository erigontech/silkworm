// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/execution/api/client.hpp>
#include <silkworm/sync/block_exchange.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>

namespace silkworm::chainsync {

class ChainSync {
  public:
    ChainSync(IBlockExchange&, execution::api::Client&);
    virtual ~ChainSync() = default;

    ChainSync(const ChainSync&) = delete;
    ChainSync& operator=(const ChainSync&) = delete;

    virtual Task<void> async_run() = 0;

  protected:
    IBlockExchange& block_exchange_;
    std::shared_ptr<execution::api::Service> exec_engine_;
    ChainForkView chain_fork_view_;
};

}  // namespace silkworm::chainsync
