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
