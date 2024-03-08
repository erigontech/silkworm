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

#include <stdexcept>

#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/etl/collector_settings.hpp>
#include <silkworm/node/db/prune_mode.hpp>
#include <silkworm/node/db/stage.hpp>

namespace silkworm::stagedsync {

class CallTraceIndex : public Stage {
  public:
    CallTraceIndex(SyncContext* sync_context,
                   size_t batch_size,
                   db::etl::CollectorSettings etl_settings,
                   db::BlockAmount prune_mode);
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

    std::size_t batch_size_;
    db::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_;

    std::unique_ptr<db::etl_mdbx::Collector> call_from_collector_;
    std::unique_ptr<db::etl_mdbx::Collector> call_to_collector_;
    std::unique_ptr<db::bitmap::IndexLoader> index_loader_;

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
