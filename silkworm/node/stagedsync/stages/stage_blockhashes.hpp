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

#include <silkworm/db/etl/collector_settings.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class BlockHashes final : public Stage {
  public:
    explicit BlockHashes(SyncContext* sync_context, db::etl::CollectorSettings etl_settings)
        : Stage(sync_context, db::stages::kBlockHashesKey),
          etl_settings_(std::move(etl_settings)) {}
    BlockHashes(const BlockHashes&) = delete;  // not copyable
    BlockHashes(BlockHashes&&) = delete;       // nor movable
    ~BlockHashes() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    db::etl::CollectorSettings etl_settings_;
    std::unique_ptr<db::etl_mdbx::Collector> collector_{nullptr};

    /* Stats */
    std::atomic_uint32_t current_phase_{0};
    std::atomic<BlockNum> reached_block_num_{0};

    void collect_and_load(db::RWTxn& txn, BlockNum from,
                          BlockNum to);  // Accrues canonical hashes in collector and loads them
};

}  // namespace silkworm::stagedsync
