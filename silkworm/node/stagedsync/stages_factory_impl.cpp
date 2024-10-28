/*
   Copyright 2024 The Silkworm Authors

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

#include "stages_factory_impl.hpp"

#include <silkworm/db/stages.hpp>
#include <silkworm/node/stagedsync/stages/stage_blockhashes.hpp>
#include <silkworm/node/stagedsync/stages/stage_bodies.hpp>
#include <silkworm/node/stagedsync/stages/stage_call_trace_index.hpp>
#include <silkworm/node/stagedsync/stages/stage_execution.hpp>
#include <silkworm/node/stagedsync/stages/stage_finish.hpp>
#include <silkworm/node/stagedsync/stages/stage_hashstate.hpp>
#include <silkworm/node/stagedsync/stages/stage_headers.hpp>
#include <silkworm/node/stagedsync/stages/stage_history_index.hpp>
#include <silkworm/node/stagedsync/stages/stage_interhashes.hpp>
#include <silkworm/node/stagedsync/stages/stage_log_index.hpp>
#include <silkworm/node/stagedsync/stages/stage_senders.hpp>
#include <silkworm/node/stagedsync/stages/stage_triggers.hpp>
#include <silkworm/node/stagedsync/stages/stage_tx_lookup.hpp>

namespace silkworm::stagedsync {

using namespace db::stages;

StageContainer StagesFactoryImpl::make(SyncContext& sync_context) const {
    SyncContext* sync_context_ptr = &sync_context;
    StageContainer stages;
    stages.emplace(kHeadersKey, std::make_unique<HeadersStage>(sync_context_ptr, data_model_factory_));
    stages.emplace(kBlockBodiesKey, bodies_stage_factory_(sync_context_ptr));
    stages.emplace(kBlockHashesKey, std::make_unique<BlockHashes>(sync_context_ptr, settings_.etl()));
    stages.emplace(kSendersKey, std::make_unique<Senders>(sync_context_ptr, data_model_factory_, *settings_.chain_config, settings_.batch_size, settings_.etl(), settings_.prune_mode.senders()));
    stages.emplace(kExecutionKey, std::make_unique<Execution>(sync_context_ptr, data_model_factory_, *settings_.chain_config, settings_.batch_size, settings_.prune_mode));
    stages.emplace(kHashStateKey, std::make_unique<HashState>(sync_context_ptr, settings_.etl()));
    stages.emplace(kIntermediateHashesKey, std::make_unique<InterHashes>(sync_context_ptr, data_model_factory_, settings_.etl()));
    stages.emplace(kHistoryIndexKey, std::make_unique<HistoryIndex>(sync_context_ptr, settings_.batch_size, settings_.etl(), settings_.prune_mode.history()));
    stages.emplace(kLogIndexKey, std::make_unique<LogIndex>(sync_context_ptr, settings_.batch_size, settings_.etl(), settings_.prune_mode.history()));
    stages.emplace(kCallTracesKey, std::make_unique<CallTraceIndex>(sync_context_ptr, settings_.batch_size, settings_.etl(), settings_.prune_mode.call_traces()));
    stages.emplace(kTxLookupKey, std::make_unique<TxLookup>(sync_context_ptr, data_model_factory_, settings_.etl(), settings_.prune_mode.tx_index()));
    stages.emplace(kTriggersStageKey, std::make_unique<TriggersStage>(sync_context_ptr));
    stages.emplace(kFinishKey, std::make_unique<Finish>(sync_context_ptr, settings_.build_info.build_description));
    return stages;
}

StageContainerFactory StagesFactoryImpl::to_factory(StagesFactoryImpl instance) {
    return [instance = std::move(instance)](SyncContext& sync_context) -> StageContainer {
        return instance.make(sync_context);
    };
}

}  // namespace silkworm::stagedsync
