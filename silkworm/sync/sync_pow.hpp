// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/io_context.hpp>

#include <silkworm/execution/api/client.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/active_component.hpp>
#include <silkworm/sync/internals/chain_fork_view.hpp>
#include <silkworm/sync/messages/internal_message.hpp>

#include "block_exchange.hpp"
#include "chain_sync.hpp"

namespace silkworm::chainsync {

namespace asio = boost::asio;

class PoWSync : public ChainSync, ActiveComponent {
  public:
    PoWSync(IBlockExchange&, execution::api::Client&);

    Task<void> async_run() override;

    void execution_loop() final; /*[[long_running]]*/

  private:
    using UnwindPoint = BlockId;

    BlockId resume();
    BlockId forward_and_insert_blocks();
    void unwind(UnwindPoint, std::optional<Hash> bad_block);
    std::shared_ptr<InternalMessage<void>> update_bad_headers(std::set<Hash>);

    void send_new_block_announcements(Blocks blocks);
    void send_new_block_hash_announcements();

    asio::io_context ioc_;
    bool is_first_sync_{true};
};

}  // namespace silkworm::chainsync
