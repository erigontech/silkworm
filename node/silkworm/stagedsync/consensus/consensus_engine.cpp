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

#include "consensus_engine.hpp"

namespace silkworm::stagedsync {

ConsensusEngine::ConsensusEngine(const NodeSettings& ns, const db::ROAccess& dba, ExecutionEngine& ee)
    : node_settings_{ns},
      db_access_{dba},
      exec_engine_{ee} {
}

void ConsensusEngine::execution_loop() {
    // todo: implement

    // Main algo:
    //    1. result = exec_engine_.forward(...)
    //    2. if (result == unwind_needed) exec_engine_.unwind(...)
    //    3. prune(...)

    /*
    switch (forward_result) {
        case Stage::Result::kSuccess:
        case Stage::Result::kWrongFork:
        case Stage::Result::kInvalidBlock:
        case Stage::Result::kWrongStateRoot:
            break;  // Do nothing. Unwind is triggered afterwards
        case Stage::Result::kStoppedByEnv:
            should_end_loop = true;
            break;
        default:
            throw StageError(forward_result);
    }
    */
};

}  // namespace silkworm::stagedsync