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

#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/concurrency/active_component.hpp>
#include <silkworm/downloader/block_exchange.hpp>
#include <silkworm/downloader/messages/internal_message.hpp>
#include <silkworm/stagedsync/execution_engine.hpp>

#include "stage_bodies.hpp"
#include "stage_headers.hpp"

namespace silkworm::stagedsync::consensus {

class ConsensusEngine : public ActiveComponent {
  public:
    ConsensusEngine(NodeSettings&, db::ROAccess, BlockExchange&, ExecutionEngine&);

    void execution_loop() final; /*[[long_running]]*/

  private:
    auto foward_and_insert_blocks(HeadersStage&, BodiesStage&) -> Stage::NewHeight;
    void unwind(HeadersStage&, BodiesStage&, Stage::UnwindPoint);
    auto update_bad_headers(std::set<Hash>) -> std::shared_ptr<InternalMessage<void>>;

    NodeSettings& node_settings_;
    db::ROAccess db_access_;
    BlockExchange& block_exchange_;
    ExecutionEngine& exec_engine_;
};

}  // namespace silkworm::stagedsync::consensus
