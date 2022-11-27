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

auto ConsensusEngine::foward_and_insert_blocks(HeadersStage& headers_stage, BodiesStage& bodies_stage) -> Stage::NewHeight {
    using NewHeight = Stage::NewHeight;

    NewHeight as_far_as_possible{};

    auto new_height = headers_stage.forward(as_far_as_possible);

    auto bodies_height = bodies_stage.forward(new_height);
    if (new_height.block_num != bodies_height.block_num) {
        // ???
    }

    return new_height;
}

void ConsensusEngine::unwind(HeadersStage& headers_stage, BodiesStage& bodies_stage, Stage::UnwindPoint unwind_point) {

    bodies_stage.unwind(unwind_point);

    headers_stage.unwind(unwind_point);
}

void ConsensusEngine::execution_loop() {
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;
    using NewHeight = Stage::NewHeight;
    using UnwindPoint = Stage::UnwindPoint;

    while(!is_stopping()) {

        HeadersStage headers_stage{block_exchange_, exec_engine_};
        BodiesStage bodies_stage{block_exchange_, exec_engine_};

        NewHeight new_height = foward_and_insert_blocks(headers_stage, bodies_stage);

        auto verification = exec_engine_.verify_chain(new_height.hash);

        if (std::holds_alternative<InvalidChain>(verification)) {
            auto invalid_chain = std::get<InvalidChain>(verification);

            unwind(headers_stage, bodies_stage, invalid_chain);

            exec_engine_.update_fork_choice(invalid_chain.unwind_head);

            continue;
        } else if (std::holds_alternative<ValidationError>(verification)) {
            throw std::logic_error("Consensus, validation error");
        }

        auto valid_chain = std::get<ValidChain>(verification);

        if (valid_chain.current_point != new_height.block_num) {
            // ???
        }

        exec_engine_.update_fork_choice(new_height.hash);
    }

};

}  // namespace silkworm::stagedsync