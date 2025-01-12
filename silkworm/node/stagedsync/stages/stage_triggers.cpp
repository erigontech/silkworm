// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    // Update its own progress to the previous stage progress to satisfy the execution pipeline constraints
    const BlockNum previous_stage_progress = db::stages::read_stage_progress(tx, db::stages::kTxLookupKey);
    update_progress(tx, previous_stage_progress);
    tx.commit_and_renew();

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
