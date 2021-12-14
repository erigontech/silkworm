/*
   Copyright 2021 The Silkworm Authors

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

#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/recovery/recovery_farm.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

StageResult Senders::forward(db::RWTxn& txn) {
    // Create farm instance and do work
    // Max number of workers is set to number of cores - 1 (one thread is left for main)
    etl::Collector collector(node_settings_->data_directory->etl().path(), node_settings_->etl_buffer_size);
    recovery::RecoveryFarm farm(txn, collector, std::thread::hardware_concurrency() - 1, node_settings_->batch_size);

    const auto res{farm.recover()};
    if (res == StageResult::kSuccess) {
        txn.commit();
    }
    return res;
}

StageResult Senders::unwind(db::RWTxn& txn, BlockNum to) {
    const StageResult res{recovery::RecoveryFarm::unwind(*txn, to)};
    if (res == StageResult::kSuccess) {
        txn.commit();
    }
    return res;
}

StageResult Senders::prune(db::RWTxn& txn) {

    auto progress{get_progress(txn)};
    auto prune_to_block{node_settings_->prune_mode->senders().value_from_head(progress)};
    if (prune_to_block) {
        auto upper_key{db::block_key(prune_to_block + 1)};
        auto prune_table{db::open_cursor(*txn, db::table::kSenders)};
        db::cursor_erase(prune_table, upper_key, db::CursorMoveDirection::Reverse);
    }

    return StageResult::kSuccess;
}

}  // namespace silkworm::stagedsync
