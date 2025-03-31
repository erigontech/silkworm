// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class LogIndex : public Stage {
  public:
    LogIndex(
        SyncContext* sync_context,
        size_t batch_size,
        datastore::etl::CollectorSettings etl_settings,
        db::BlockAmount prune_mode_history)
        : Stage(sync_context, db::stages::kLogIndexKey),
          batch_size_(batch_size),
          etl_settings_(std::move(etl_settings)),
          prune_mode_history_(prune_mode_history) {}
    LogIndex(const LogIndex&) = delete;  // not copyable
    LogIndex(LogIndex&&) = delete;       // nor movable
    ~LogIndex() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    size_t batch_size_;
    datastore::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_history_;

    std::unique_ptr<datastore::kvdb::Collector> topics_collector_;
    std::unique_ptr<datastore::kvdb::Collector> addresses_collector_;
    std::unique_ptr<datastore::kvdb::bitmap::IndexLoader> index_loader_;

    std::atomic_bool loading_{false};  // Whether we're in ETL loading phase
    std::string current_source_;       // Current source of data
    std::string current_target_;       // Current target of transformed data
    std::string current_key_;          // Actual processing key

    void forward_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void prune_impl(db::RWTxn& txn, BlockNum threshold, const db::MapConfig& target);

    //! \brief Collects bitmaps of block numbers for each log entry
    void collect_bitmaps_from_logs(db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to);

    //! \brief Collects unique keys for log entries within provided boundaries
    void collect_unique_keys_from_logs(
        db::RWTxn& txn,
        const db::MapConfig& source_config,
        BlockNum from, BlockNum to,
        std::map<Bytes, bool>& addresses,
        std::map<Bytes, bool>& topics);

    void reset_log_progress();  // Clears out all logging vars
};

}  // namespace silkworm::stagedsync
