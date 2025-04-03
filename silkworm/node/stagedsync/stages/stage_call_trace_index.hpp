// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class CallTraceIndex : public Stage {
  public:
    CallTraceIndex(SyncContext* sync_context,
                   size_t batch_size,
                   datastore::etl::CollectorSettings etl_settings,
                   db::BlockAmount prune_mode);
    CallTraceIndex(const CallTraceIndex&) = delete;  // not copyable
    CallTraceIndex(CallTraceIndex&&) = delete;       // nor movable
    ~CallTraceIndex() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    void forward_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void prune_impl(db::RWTxn& txn, BlockNum threshold, const db::MapConfig& target);

    //! \brief Collect bitmaps of block numbers for each call trace entry
    void collect_bitmaps_from_call_traces(
        db::RWTxn& txn, const db::MapConfig& source_config, BlockNum from, BlockNum to);

    //! \brief Collect unique keys for call trace entries within provided boundaries
    void collect_unique_keys_from_call_traces(
        db::RWTxn& txn,
        const db::MapConfig& source_config,
        BlockNum from, BlockNum to,
        std::map<Bytes, bool>& senders,
        std::map<Bytes, bool>& receivers);

    void reset_log_progress();  // Clears out all logging vars

    size_t batch_size_;
    datastore::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_;

    std::unique_ptr<datastore::kvdb::Collector> call_from_collector_;
    std::unique_ptr<datastore::kvdb::Collector> call_to_collector_;
    std::unique_ptr<datastore::kvdb::bitmap::IndexLoader> index_loader_;

    //! Flag indicating if we're in ETL loading phase (for logging purposes)
    std::atomic_bool loading_{false};

    //! Current source of data (for logging purposes)
    std::string current_source_;

    //! Current target of transformed data (for logging purposes)
    std::string current_target_;

    //! Actual processing key (for logging purposes)
    std::string current_key_;
};

}  // namespace silkworm::stagedsync
