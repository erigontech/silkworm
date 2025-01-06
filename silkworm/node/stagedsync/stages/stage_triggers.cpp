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

#include "stage_triggers.hpp"

#include <gsl/util>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::stagedsync {

TriggersStage::TriggersStage(SyncContext* sync_context)
    : Stage(sync_context, db::stages::kTriggersStageKey) {
}

Stage::Result TriggersStage::forward(db::RWTxn& tx) {
    current_tx_ = &tx;
    [[maybe_unused]] auto _ = gsl::finally([this] {
        current_tx_ = nullptr;
    });

    ioc_.restart();
    ioc_.run();

    return Stage::Result::kSuccess;
}

Task<void> TriggersStage::schedule(std::function<void(db::RWTxn&)> callback) {
    auto task_caller = [](auto* self, auto trigger) -> Task<void> {
        db::RWTxn* tx = self->current_tx_;
        SILKWORM_ASSERT(tx);
        trigger(*tx);
        co_return;
    };
    return concurrency::spawn_task(ioc_, task_caller(this, std::move(callback)));
}

bool TriggersStage::stop() {
    ioc_.stop();
    return Stage::stop();
}

}  // namespace silkworm::stagedsync
