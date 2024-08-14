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

#include <cassert>

#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <gsl/util>

#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

namespace silkworm::stagedsync {

TriggersStage::TriggersStage(SyncContext* sync_context)
    : Stage(sync_context, db::stages::kTriggersStageKey) {
}

Stage::Result TriggersStage::forward(db::RWTxn& tx) {
    current_tx_ = &tx;
    [[maybe_unused]] auto _ = gsl::finally([this] {
        current_tx_ = nullptr;
    });

    io_context_.restart();
    io_context_.run();

    return Stage::Result::kSuccess;
}

Task<void> TriggersStage::schedule(std::function<Task<void>(db::RWTxn&)> task) {
    auto task_caller = [this, t = std::move(task)]() -> Task<void> {
        db::RWTxn* tx = this->current_tx_;
        assert(tx);
        co_await t(*tx);
    };
    return concurrency::co_spawn_sw(io_context_, task_caller(), boost::asio::use_awaitable);
}

bool TriggersStage::stop() {
    io_context_.stop();
    return Stage::stop();
}

}  // namespace silkworm::stagedsync
