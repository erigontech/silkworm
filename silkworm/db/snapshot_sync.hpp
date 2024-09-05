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

#include <atomic>
#include <filesystem>
#include <functional>
#include <latch>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/freezer.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/snapshot_merger.hpp>
#include <silkworm/db/snapshots/bittorrent/client.hpp>
#include <silkworm/db/snapshots/config.hpp>
#include <silkworm/db/snapshots/snapshot_repository.hpp>
#include <silkworm/db/snapshots/snapshot_settings.hpp>
#include <silkworm/db/stage_scheduler.hpp>
#include <silkworm/infra/concurrency/awaitable_condition_variable.hpp>
#include <silkworm/infra/concurrency/stoppable.hpp>

namespace silkworm::db {

class SnapshotSync {
  public:
    SnapshotSync(
        snapshots::SnapshotSettings settings,
        ChainId chain_id,
        mdbx::env& chaindata_env,
        std::filesystem::path tmp_dir_path,
        stagedsync::StageScheduler& stage_scheduler);

    Task<void> run();

    Task<void> download_and_index_snapshots();
    Task<void> download_snapshots();
    Task<void> wait_for_setup();

  protected:
    Task<void> setup_and_run();
    Task<void> setup();
    Task<void> build_missing_indexes();
    void update_database(db::RWTxn& txn, BlockNum max_block_available, std::function<bool()> is_stopping);
    void update_block_headers(db::RWTxn& txn, BlockNum max_block_available, std::function<bool()> is_stopping);
    void update_block_bodies(db::RWTxn& txn, BlockNum max_block_available);
    static void update_block_hashes(db::RWTxn& txn, BlockNum max_block_available);
    static void update_block_senders(db::RWTxn& txn, BlockNum max_block_available);
    snapshots::SnapshotRepository& repository() { return repository_; };

    snapshots::SnapshotSettings settings_;
    const snapshots::Config snapshots_config_;
    mdbx::env& chaindata_env_;

    snapshots::SnapshotRepository repository_;

    snapshots::bittorrent::BitTorrentClient client_;

    db::Freezer snapshot_freezer_;
    db::SnapshotMerger snapshot_merger_;

    std::latch is_stopping_latch_;
    std::atomic_bool setup_done_;
    concurrency::AwaitableConditionVariable setup_done_cond_var_;
    std::mutex setup_done_mutex_;
};

}  // namespace silkworm::db
