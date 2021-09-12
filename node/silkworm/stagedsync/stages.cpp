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

std::vector<Stage> get_archive_node_stages() {
    return {
        {stage_headers, nullptr, nullptr, 1},
        {stage_blockhashes, unwind_blockhashes, nullptr, 2},
        {stage_bodies, nullptr, nullptr, 3},
        {stage_senders, unwind_senders, nullptr, 4},
        {stage_execution, unwind_execution, nullptr, 5},
        {stage_hashstate, unwind_hashstate, nullptr, 6},
        {stage_interhashes, unwind_interhashes, nullptr, 7},
        {stage_account_history, unwind_account_history, nullptr, 8},
        {stage_storage_history, unwind_storage_history, nullptr, 9},
        {stage_log_index, unwind_log_index, nullptr, 10},
        {stage_tx_lookup, unwind_tx_lookup, nullptr, 11},
    };
}

std::vector<Stage> get_pruned_node_stages() {
    return {
        {stage_headers, nullptr, nullptr, 1},
        {stage_blockhashes, unwind_blockhashes, nullptr, 2},
        {stage_bodies, nullptr, nullptr, 3},
        {stage_senders, unwind_senders, prune_senders, 4},
        {stage_execution, unwind_execution, prune_execution, 5},
        {stage_hashstate, unwind_hashstate, nullptr, 6},
        {stage_interhashes, unwind_interhashes, nullptr, 7},
        {stage_account_history, unwind_account_history, prune_account_history, 8},
        {stage_storage_history, unwind_storage_history, prune_storage_history, 9},
        {stage_log_index, unwind_log_index, prune_log_index, 10},
        {stage_tx_lookup, unwind_tx_lookup, prune_tx_lookup, 11},
    };
}

std::vector<Stage> get_miner_mode_stages() {
    return {
        {stage_headers, nullptr, nullptr, 1},
        {stage_blockhashes, unwind_blockhashes, nullptr, 2},
        {stage_bodies, nullptr, nullptr, 3},
        {stage_senders, unwind_senders, prune_senders, 4},
        {stage_execution, unwind_execution, prune_execution, 5},
        {stage_hashstate, unwind_hashstate, nullptr, 6},
        {stage_interhashes, unwind_interhashes, nullptr, 7},
    };
}

}  // namespace silkworm::stagedsync
