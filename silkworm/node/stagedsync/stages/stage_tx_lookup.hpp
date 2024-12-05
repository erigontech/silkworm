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

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class TxLookup : public Stage {
  public:
    TxLookup(
        SyncContext* sync_context,
        db::DataModelFactory data_model_factory,
        datastore::etl::CollectorSettings etl_settings,
        db::BlockAmount prune_mode_tx_index)
        : Stage(sync_context, db::stages::kTxLookupKey),
          data_model_factory_(std::move(data_model_factory)),
          etl_settings_(std::move(etl_settings)),
          prune_mode_tx_index_(prune_mode_tx_index) {}
    TxLookup(const TxLookup&) = delete;  // not copyable
    TxLookup(TxLookup&&) = delete;       // nor movable
    ~TxLookup() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    db::DataModelFactory data_model_factory_;
    datastore::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_tx_index_;

    std::unique_ptr<datastore::kvdb::Collector> collector_;

    std::atomic_bool loading_{false};  // Whether we're in ETL loading phase
    std::string current_source_;       // Current source of data
    std::string current_target_;       // Current target of transformed data
    std::string current_key_;          // Actual processing key

    void forward_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void unwind_impl(db::RWTxn& txn, BlockNum from, BlockNum to);
    void prune_impl(db::RWTxn& txn, BlockNum from, BlockNum to);

    void reset_log_progress();  // Clears out all logging vars

    void collect_transaction_hashes_from_canonical_bodies(db::RWTxn& txn,
                                                          BlockNum from, BlockNum to,
                                                          bool for_deletion);
};
}  // namespace silkworm::stagedsync
