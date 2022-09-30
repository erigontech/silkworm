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

#include <silkworm/stagedsync/stage.hpp>
#include <silkworm/stagedsync/stage_senders/recovery_farm.hpp>

namespace silkworm::stagedsync {

class Senders final : public Stage {
  public:
    explicit Senders(NodeSettings* node_settings, SyncContext* sync_context)
        : Stage(sync_context, db::stages::kSendersKey, node_settings){};
    ~Senders() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;
    bool stop() final;

  private:
    std::unique_ptr<recovery::RecoveryFarm> farm_{nullptr};

    // Logging
    std::string current_key_{};
};

}  // namespace silkworm::stagedsync
