// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class HistoryIndex : public Stage {
  public:
    HistoryIndex(
        SyncContext* sync_context,
        size_t batch_size,
        datastore::etl::CollectorSettings etl_settings,
        db::BlockAmount prune_mode_history)
        : Stage(sync_context, db::stages::kHistoryIndexKey),
          batch_size_(batch_size),
          etl_settings_(std::move(etl_settings)),
          prune_mode_history_(prune_mode_history) {}
    HistoryIndex(const HistoryIndex&) = delete;  // not copyable
    HistoryIndex(HistoryIndex&&) = delete;       // nor movable
    ~HistoryIndex() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    size_t batch_size_;
    datastore::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_history_;

    std::unique_ptr<datastore::kvdb::Collector> collector_;
    std::unique_ptr<datastore::kvdb::bitmap::IndexLoader> index_loader_;

    std::atomic_bool loading_{false};  // Whether we're in ETL loading phase
    std::string current_source_;       // Current source of data
    std::string current_target_;       // Current target of transformed data
    std::string current_key_;          // Actual processing key

    Stage::Result forward_impl(db::RWTxn& txn, BlockNum from, BlockNum to, bool storage);
    Stage::Result unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to, bool storage);
    Stage::Result prune_impl(db::RWTxn& txn, BlockNum threshold, BlockNum to, bool storage);

    //! \brief Collects bitmaps of block numbers changes for each account within provided
    //! changeset boundaries
    void collect_bitmaps_from_changeset(db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to,
                                        bool storage);

    //! \brief Collects unique keys touched by changesets within provided boundaries
    std::map<Bytes, bool> collect_unique_keys_from_changeset(
        db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to, bool storage);

    void reset_log_progress();  // Clears out all logging vars
};

}  // namespace silkworm::stagedsync
