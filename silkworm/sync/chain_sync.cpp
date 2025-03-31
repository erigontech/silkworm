// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_sync.hpp"

namespace silkworm::chainsync {

ChainSync::ChainSync(IBlockExchange& block_exchange, execution::api::Client& exec_client)
    : block_exchange_{block_exchange},
      exec_engine_{exec_client.service()},
      chain_fork_view_{ChainForkView::head_at_genesis(block_exchange.chain_config())} {
}

}  // namespace silkworm::chainsync
