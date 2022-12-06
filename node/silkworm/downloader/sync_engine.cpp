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

#include "sync_engine.hpp"

namespace silkworm::chainsync {

SyncEngine::SyncEngine(NodeSettings&, db::ROAccess dba, BlockExchange& be, stagedsync::ExecutionEngine& ee)
    : //node_settings_{ns},
      db_access_{dba},
      block_exchange_{be},
      exec_engine_{ee} {
}

auto SyncEngine::forward_and_insert_blocks(HeadersStage& headers_stage, BodiesStage& bodies_stage) -> Stage::NewHeight {
    using NewHeight = Stage::NewHeight;

    NewHeight as_far_as_possible{};

    auto new_height = headers_stage.forward(as_far_as_possible);

    auto bodies_height = bodies_stage.forward(new_height);
    if (new_height.block_num != bodies_height.block_num) {
        // ???
    }

    return new_height;
}

void SyncEngine::unwind(HeadersStage& headers_stage, BodiesStage& bodies_stage, Stage::UnwindPoint unwind_point) {
    bodies_stage.unwind(unwind_point);

    headers_stage.unwind(unwind_point);
}

void SyncEngine::execution_loop() {
    using namespace stagedsync;
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;
    using NewHeight = Stage::NewHeight;
    //using UnwindPoint = Stage::UnwindPoint;

    while (!is_stopping()) {
        HeadersStage headers_stage{block_exchange_, exec_engine_};
        BodiesStage bodies_stage{block_exchange_, exec_engine_};

        NewHeight new_height = forward_and_insert_blocks(headers_stage, bodies_stage);

        auto verification = exec_engine_.verify_chain(new_height.hash);

        if (std::holds_alternative<InvalidChain>(verification)) {
            auto invalid_chain = std::get<InvalidChain>(verification);

            unwind(headers_stage, bodies_stage, {invalid_chain.unwind_point});

            if (!invalid_chain.bad_headers.empty()) {
                update_bad_headers(std::move(invalid_chain.bad_headers));
            }

            exec_engine_.notify_fork_choice_updated(invalid_chain.unwind_head);

            continue;
        } else if (std::holds_alternative<ValidationError>(verification)) {
            throw std::logic_error("Consensus, validation error");
        }

        auto valid_chain = std::get<ValidChain>(verification);

        if (valid_chain.current_point != new_height.block_num) {
            // ???
        }

        exec_engine_.notify_fork_choice_updated(new_height.hash);
    }
};

auto SyncEngine::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [bads = std::move(bad_headers)](HeaderChain& wc, BodySequence&) { wc.add_bad_headers(bads); });

    block_exchange_.accept(message);

    return message;
}

}  // namespace silkworm::chainsync