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

#include <stdexcept>

#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

class LogIndex : public Stage {
  public:
    explicit LogIndex(NodeSettings* node_settings, SyncContext* sync_context)
        : Stage(sync_context, db::stages::kLogIndexKey, node_settings){};
    ~LogIndex() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    std::unique_ptr<db::etl::Collector> topics_collector_{nullptr};
    std::unique_ptr<db::etl::Collector> addresses_collector_{nullptr};
    std::unique_ptr<db::bitmap::IndexLoader> index_loader_{nullptr};

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
