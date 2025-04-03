// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <functional>

#include <boost/signals2.hpp>

#include "common/step.hpp"
#include "data_migration.hpp"
#include "snapshots/snapshot_repository.hpp"
#include "snapshots/snapshot_size.hpp"

namespace silkworm::datastore {

class SnapshotMerger : public DataMigration {
  public:
    SnapshotMerger(
        snapshots::SnapshotRepository& snapshots,
        std::filesystem::path tmp_dir_path)
        : snapshots_(snapshots),
          tmp_dir_path_(std::move(tmp_dir_path)) {}

    boost::signals2::scoped_connection on_snapshot_merged(const std::function<void(StepRange)>& callback);

  private:
    static constexpr size_t kBatchSize = 10;
    static constexpr size_t kMaxSnapshotSize = snapshots::kMaxMergerSnapshotSize;

    const char* name() const override { return "SnapshotMerger"; }
    std::unique_ptr<DataMigrationCommand> next_command() override;
    std::shared_ptr<DataMigrationResult> migrate(std::unique_ptr<DataMigrationCommand> command) override;
    void index(std::shared_ptr<DataMigrationResult> result) override;
    void commit(std::shared_ptr<DataMigrationResult> result) override;
    Task<void> cleanup() override;

    snapshots::SnapshotRepository& snapshots_;
    std::filesystem::path tmp_dir_path_;
    boost::signals2::signal<void(StepRange)> on_snapshot_merged_signal_;
};

}  // namespace silkworm::datastore
