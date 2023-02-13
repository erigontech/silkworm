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

#include <silkworm/node/common/log.hpp>
#include <silkworm/node/common/settings.hpp>
#include <silkworm/node/concurrency/active_component.hpp>
#include <silkworm/node/downloader/internals/chain_fork_view.hpp>
#include <silkworm/node/downloader/messages/internal_message.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

#include "block_exchange.hpp"

namespace silkworm::chainsync {

class SyncEngine : public ActiveComponent {
  public:
    SyncEngine(BlockExchange&, stagedsync::ExecutionEngine&);

    void execution_loop() final; /*[[long_running]]*/

  private:
    struct NewHeight {
        BlockNum block_num;
        Hash hash;
    };
    struct UnwindPoint {
        BlockNum block_num;
        Hash hash;
        std::optional<Hash> bad_block;
    };

    auto resume() -> NewHeight;
    auto forward_and_insert_blocks() -> NewHeight;
    void unwind(UnwindPoint);
    auto update_bad_headers(std::set<Hash>) -> std::shared_ptr<InternalMessage<void>>;

    void send_new_block_announcements(Blocks&& blocks);
    void send_new_block_hash_announcements();

    BlockExchange& block_exchange_;
    stagedsync::ExecutionEngine& exec_engine_;
    ChainForkView chain_fork_view_;
    bool is_first_sync_{true};
};

}  // namespace silkworm::chainsync
