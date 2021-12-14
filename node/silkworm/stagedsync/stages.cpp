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

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

StageResult no_unwind(db::RWTxn&, const std::filesystem::path&, uint64_t) { return StageResult::kSuccess; }
StageResult no_prune(db::RWTxn&, const std::filesystem::path&, uint64_t)  { return StageResult::kSuccess; }

std::vector<Stage> get_archive_node_stages() {
    return {
        {stage_headers,         no_unwind,              no_prune, 1},
        {stage_bodies,          no_unwind,              no_prune, 3},
        {stage_execution,       unwind_execution,       no_prune, 5},
        {stage_hashstate,       unwind_hashstate,       no_prune, 6},
        {stage_interhashes,     unwind_interhashes,     no_prune, 7},
        {stage_account_history, unwind_account_history, no_prune, 8},
        {stage_storage_history, unwind_storage_history, no_prune, 9},
        {stage_log_index,       unwind_log_index,       no_prune, 10},
        {stage_tx_lookup,       unwind_tx_lookup,       no_prune, 11},
    };
}

std::vector<Stage> get_pruned_node_stages() {
    return {
        {stage_headers,         no_unwind,              no_prune,              1},
        {stage_bodies,          no_unwind,              no_prune,              3},
        {stage_execution,       unwind_execution,       prune_execution,       5},
        {stage_hashstate,       unwind_hashstate,       no_prune,              6},
        {stage_interhashes,     unwind_interhashes,     no_prune,              7},
        {stage_account_history, unwind_account_history, prune_account_history, 8},
        {stage_storage_history, unwind_storage_history, prune_storage_history, 9},
        {stage_log_index,       unwind_log_index,       prune_log_index,      10},
        {stage_tx_lookup,       unwind_tx_lookup,       prune_tx_lookup,      11},
    };
}

std::vector<Stage> get_miner_mode_stages() {
    return {
        {stage_headers,         no_unwind,              no_prune,        1},
        {stage_bodies,          no_unwind,              no_prune,        3},
        {stage_execution,       unwind_execution,       prune_execution, 5},
        {stage_hashstate,       unwind_hashstate,       no_prune,        6},
        {stage_interhashes,     unwind_interhashes,     no_prune,        7},
    };
}

}  // namespace silkworm::stagedsync
