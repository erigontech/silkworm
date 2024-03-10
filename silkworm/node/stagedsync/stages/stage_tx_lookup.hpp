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

#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/etl/collector_settings.hpp>
#include <silkworm/node/db/prune_mode.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

class TxLookup : public Stage {
  public:
    TxLookup(
        SyncContext* sync_context,
        db::etl::CollectorSettings etl_settings,
        db::BlockAmount prune_mode_tx_index)
        : Stage(sync_context, db::stages::kTxLookupKey),
          etl_settings_(std::move(etl_settings)),
          prune_mode_tx_index_(prune_mode_tx_index) {}
    ~TxLookup() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    db::etl::CollectorSettings etl_settings_;
    db::BlockAmount prune_mode_tx_index_;

    std::unique_ptr<db::etl_mdbx::Collector> collector_{nullptr};

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
