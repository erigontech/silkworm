// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "datastore/data_migration.hpp"
#include "datastore/kvdb/mdbx.hpp"
#include "datastore/snapshots/snapshot_repository.hpp"
#include "datastore/stage_scheduler.hpp"

namespace silkworm::db {

class Freezer : public datastore::DataMigration {
  public:
    using DataMigrationCommand = datastore::DataMigrationCommand;
    using DataMigrationResult = datastore::DataMigrationResult;

    Freezer(
        datastore::kvdb::ROAccess db_access,
        snapshots::SnapshotRepository& snapshots,
        datastore::StageScheduler& stage_scheduler,
        std::filesystem::path tmp_dir_path,
        bool keep_blocks)
        : db_access_(std::move(db_access)),
          snapshots_(snapshots),
          stage_scheduler_(stage_scheduler),
          tmp_dir_path_(std::move(tmp_dir_path)),
          keep_blocks_(keep_blocks) {}

  private:
    static constexpr size_t kChunkSize = 1000;

    const char* name() const override { return "Freezer"; }
    std::unique_ptr<DataMigrationCommand> next_command() override;
    std::shared_ptr<DataMigrationResult> migrate(std::unique_ptr<DataMigrationCommand> command) override;
    void index(std::shared_ptr<DataMigrationResult> result) override;
    void commit(std::shared_ptr<DataMigrationResult> result) override;
    Task<void> cleanup() override;
    BlockNumRange cleanup_range();
    void prune_collations(datastore::kvdb::RWTxn& db_tx, BlockNumRange range) const;

    datastore::kvdb::ROAccess db_access_;
    snapshots::SnapshotRepository& snapshots_;
    datastore::StageScheduler& stage_scheduler_;
    std::filesystem::path tmp_dir_path_;
    bool keep_blocks_;
};

}  // namespace silkworm::db
