#include "stagedsync.hpp"

namespace silkworm::stagedsync{

std::vector<Stage> get_default_stages() {
    return std::vector<Stage>({{stage_headers, unwind_headers, 1},
                               {stage_blockhashes, unwind_blockhashes, 2},
                               {stage_bodies, unwind_bodies, 3},
                               {stage_senders, unwind_senders, 4},
                               {stage_execution, unwind_execution, 5},
                               {stage_hashstate, unwind_hashstate, 6},
                               {stage_interhashes, unwind_hashstate, 7},
                               {stage_account_history, unwind_account_history, 8},
                               {stage_storage_history, unwind_storage_history, 9},
                               {stage_log_index, unwind_log_index, 10},
                               {stage_tx_lookup, unwind_tx_lookup, 11}});
}

}
