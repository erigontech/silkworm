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

#include <silkworm/concurrency/containers.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/downloader/block_exchange.hpp>
#include <silkworm/downloader/internals/types.hpp>
#include <silkworm/downloader/messages/internal_message.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class BodiesStage : public Stage {
  public:
    BodiesStage(SyncContext*, BlockExchange&, NodeSettings*);
    BodiesStage(const BodiesStage&) = delete;  // not copyable
    BodiesStage(BodiesStage&&) = delete;       // nor movable
    ~BodiesStage();

    Stage::Result forward(db::RWTxn&) override;  // go forward, downloading headers
    Stage::Result unwind(db::RWTxn&) override;   // go backward, unwinding headers to new_height
    Stage::Result prune(db::RWTxn&) override;

  private:
    void send_body_requests();  // send requests for more bodies
    auto sync_body_sequence(BlockNum highest_body, BlockNum highest_header) -> std::shared_ptr<InternalMessage<void>>;
    auto withdraw_ready_bodies() -> std::shared_ptr<InternalMessage<std::vector<Block>>>;
    void send_announcements();

    std::vector<std::string> get_log_progress() override;  // thread safe
    std::atomic<BlockNum> current_height_{0};

    BlockExchange& block_downloader_;
};

}  // namespace silkworm::stagedsync
