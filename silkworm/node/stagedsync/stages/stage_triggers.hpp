/*
   Copyright 2024 The Silkworm Authors

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

#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class TriggersStage : public Stage, public datastore::StageScheduler {
  public:
    explicit TriggersStage(SyncContext* sync_context);
    ~TriggersStage() override = default;

    Stage::Result forward(db::RWTxn& tx) override;
    Stage::Result unwind(db::RWTxn& txn) override;

    Stage::Result prune(db::RWTxn&) override { return Stage::Result::kSuccess; }

    Task<void> schedule(std::function<void(db::RWTxn&)> callback) override;

    bool stop() override;

  protected:
    boost::asio::io_context ioc_;

  private:
    db::RWTxn* current_tx_{};
};

}  // namespace silkworm::stagedsync
