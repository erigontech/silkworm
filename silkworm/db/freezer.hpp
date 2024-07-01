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

#include "data_migration.hpp"
#include "mdbx/mdbx.hpp"
#include "snapshots/repository.hpp"

namespace silkworm::db {

class Freezer : public DataMigration {
  public:
    Freezer(
        db::ROAccess db_access,
        snapshots::SnapshotRepository& snapshots,
        std::filesystem::path tmp_dir_path)
        : db_access_(std::move(db_access)),
          snapshots_(snapshots),
          tmp_dir_path_(std::move(tmp_dir_path)) {}

  private:
    static constexpr size_t kChunkSize = 1000;

    std::unique_ptr<DataMigrationCommand> next_command() override;
    std::shared_ptr<DataMigrationResult> migrate(std::unique_ptr<DataMigrationCommand> command) override;
    void index(std::shared_ptr<DataMigrationResult> result) override;
    void commit(std::shared_ptr<DataMigrationResult> result) override;
    void cleanup() override;

    db::ROAccess db_access_;
    snapshots::SnapshotRepository& snapshots_;
    std::filesystem::path tmp_dir_path_;
};

}  // namespace silkworm::db
