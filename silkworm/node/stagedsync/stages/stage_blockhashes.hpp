// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class BlockHashes final : public Stage {
  public:
    explicit BlockHashes(SyncContext* sync_context, datastore::etl::CollectorSettings etl_settings)
        : Stage(sync_context, silkworm::db::stages::kBlockHashesKey),
          etl_settings_(std::move(etl_settings)) {}
    BlockHashes(const BlockHashes&) = delete;  // not copyable
    BlockHashes(BlockHashes&&) = delete;       // nor movable
    ~BlockHashes() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    datastore::etl::CollectorSettings etl_settings_;
    std::unique_ptr<datastore::kvdb::Collector> collector_;

    /* Stats */
    std::atomic_uint32_t current_phase_{0};
    std::atomic<BlockNum> reached_block_num_{0};

    void collect_and_load(db::RWTxn& txn, BlockNum from,
                          BlockNum to);  // Accrues canonical hashes in collector and loads them
};

}  // namespace silkworm::stagedsync
