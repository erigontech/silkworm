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
    PoWSync(BlockExchange&, execution::api::Client&);

    Task<void> async_run() override;

    void execution_loop() final; /*[[long_running]]*/

  private:
    using NewHeight = BlockId;
    using UnwindPoint = BlockId;

    NewHeight resume();
    NewHeight forward_and_insert_blocks();
    void unwind(UnwindPoint, std::optional<Hash> bad_block);
    std::shared_ptr<InternalMessage<void>> update_bad_headers(std::set<Hash>);

    void send_new_block_announcements(Blocks blocks);
    void send_new_block_hash_announcements();

    asio::io_context io_context_;
    bool is_first_sync_{true};
};

}  // namespace silkworm::chainsync
