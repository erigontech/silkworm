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
#include <magic_enum.hpp>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::stagedsync {

TriggersStage::TriggersStage(SyncContext* sync_context)
    : Stage(sync_context, db::stages::kTriggersStageKey) {
}

Stage::Result TriggersStage::forward(db::RWTxn& tx) {
    Stage::Result result = Stage::Result::kSuccess;

    operation_ = OperationType::kForward;
    try {
        current_tx_ = &tx;
        [[maybe_unused]] auto _ = gsl::finally([this] {
            current_tx_ = nullptr;
        });

        ioc_.restart();
        ioc_.run();

        const auto current_progress = get_progress(tx);
        const BlockNum previous_stage_progress = db::stages::read_stage_progress(tx, db::stages::kTxLookupKey);
        if (current_progress >= previous_stage_progress) {
            // Nothing to process
            return result;
        }
        const BlockNum segment_width{previous_stage_progress - current_progress};
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            log::Info(log_prefix_,
                      {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                       "from", std::to_string(current_progress),
                       "to", std::to_string(previous_stage_progress),
                       "span", std::to_string(segment_width)});
        }

        throw_if_stopping();
        update_progress(tx, previous_stage_progress);
        tx.commit_and_renew();
    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        result = Stage::Result::kUnexpectedError;
    }
    operation_ = OperationType::kNone;

    return result;
}

Stage::Result TriggersStage::unwind(db::RWTxn& txn) {
    Stage::Result result = Stage::Result::kSuccess;
    if (!sync_context_->unwind_point) {
        return result;
    }
    const BlockNum unwind_point = *sync_context_->unwind_point;

    operation_ = OperationType::kUnwind;
    try {
        const auto current_progress = get_progress(txn);
        if (unwind_point >= current_progress) {
            return result;
        }

        const BlockNum segment_width = current_progress - unwind_point;
        if (segment_width > db::stages::kSmallBlockSegmentWidth) {
            SILK_INFO_M(log_prefix_, {"op", std::string(magic_enum::enum_name<OperationType>(operation_)),
                                      "from", std::to_string(current_progress),
                                      "to", std::to_string(unwind_point),
                                      "span", std::to_string(segment_width)});
        }

        throw_if_stopping();
        update_progress(txn, unwind_point);
        txn.commit_and_renew();
    } catch (const StageError& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = static_cast<Stage::Result>(ex.err());
    } catch (const mdbx::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kDbError;
    } catch (const std::exception& ex) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
        result = Stage::Result::kUnexpectedError;
    } catch (...) {
        SILK_ERROR_M(log_prefix_, {"function", std::string(__FUNCTION__), "exception", "unexpected and undefined"});
        result = Stage::Result::kUnexpectedError;
    }
    operation_ = OperationType::kNone;

    return result;
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
