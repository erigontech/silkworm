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


namespace silkworm::stagedsync::consensus {

ConsensusEngine::ConsensusEngine(NodeSettings& ns, db::ROAccess& dba, BlockExchange& be, ExecutionEngine& ee)
    : node_settings_{ns},
      db_access_{dba},
      block_exchange_{be},
      exec_engine_{ee} {
}

Stage::Result ConsensusEngine::foward_and_insert_blocks(HeadersStage& headers_stage, BodiesStage& bodies_stage) {
    using NewHeight = Stage::NewHeight;

    NewHeight as_far_as_possible{};
    Stage::Result result = headers_stage.forward(as_far_as_possible);

    if (!std::holds_alternative<NewHeight>(result)) {
        return result; // unwind or error
    }

    auto new_height = std::get<NewHeight>(result);

    result = bodies_stage.forward(new_height);

    return result; // // new_height or unwind or error
}

Stage::Result ConsensusEngine::unwind(HeadersStage& headers_stage, BodiesStage& bodies_stage, Stage::UnwindPoint unwind_point) {
    using NewHeight = Stage::NewHeight;
    using UnwindPoint = Stage::UnwindPoint;
    using Error = Stage::Error;

    Stage::Result result = bodies_stage.unwind(unwind_point);

    if (std::holds_alternative<UnwindPoint>(result)) {
        throw std::logic_error("consensus_engine exception, bodies_stage unwind method cannot return unwind");
    }
    else if (std::holds_alternative<Error>(result)) {
        return result;
    }

    auto new_height = std::get<NewHeight>(result);

    if (new_height.block_num != unwind_point.block_num) {
        // ???
    }

    result = headers_stage.unwind(unwind_point);

    if (std::holds_alternative<UnwindPoint>(result)) {
        throw std::logic_error("consensus_engine exception, headers_stage unwind method cannot return unwind");
    }
    else if (std::holds_alternative<Error>(result)) {
        return result;
    }

    new_height = std::get<NewHeight>(result);

    if (new_height.block_num != unwind_point.block_num) {
        // ???
    }

    return result;
}

void ConsensusEngine::execution_loop() {
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;
    using NewHeight = Stage::NewHeight;
    using UnwindPoint = Stage::UnwindPoint;
    using Error = Stage::Error;

    while(!is_stopping()) {

        HeadersStage headers_stage{block_exchange_, exec_engine_};
        BodiesStage bodies_stage{block_exchange_, exec_engine_};

        Stage::Result result = foward_and_insert_blocks(headers_stage, bodies_stage);

        if (std::holds_alternative<UnwindPoint>(result)) {
            auto unwind_point = std::get<UnwindPoint>(result);

            unwind(headers_stage, bodies_stage, unwind_point);

            exec_engine_.update_fork_choice(unwind_point.hash);
            continue;
        } else if (std::holds_alternative<Error>(result)) {
            // ???
        }

        auto new_height = std::get<NewHeight>(result);

        auto verification = exec_engine_.verify_chain(new_height.hash);

        if (std::holds_alternative<InvalidChain>(verification)) {
            auto invalid_chain = std::get<InvalidChain>(verification);

            exec_engine_.update_fork_choice(invalid_chain.unwind_head);

            continue;
        } else if (std::holds_alternative<ValidationError>(verification)) {
            // ???
        }

        auto valid_chain = std::get<ValidChain>(verification);

        if (valid_chain.current_point != new_height.block_num) {
            // ???
        }

        exec_engine_.update_fork_choice(new_height.hash);
    }

};

}  // namespace silkworm::stagedsync