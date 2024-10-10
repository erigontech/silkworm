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

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/mdbx/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class HistoryIndex : public Stage {
  public:
    HistoryIndex(
        SyncContext* sync_context,
        size_t batch_size,
        db::etl::CollectorSettings etl_settings,
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
    db::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_history_;

    std::unique_ptr<db::etl_mdbx::Collector> collector_;
    std::unique_ptr<db::bitmap::IndexLoader> index_loader_;

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
