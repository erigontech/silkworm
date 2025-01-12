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

#include "execution_pipeline.hpp"

#include <absl/strings/str_format.h>
#include <magic_enum.hpp>

#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/stopwatch.hpp>

namespace silkworm::stagedsync {

using namespace silkworm::db::stages;

#if defined(NDEBUG)
static const std::chrono::milliseconds kStageDurationThresholdForLog{10};
#else
static const std::chrono::milliseconds kStageDurationThresholdForLog{0};
#endif

static const ExecutionPipeline::StageNames kStagesForwardOrder{
    kHeadersKey,
    kBlockHashesKey,
    kBlockBodiesKey,
    kSendersKey,
    kExecutionKey,
    kHashStateKey,
    kIntermediateHashesKey,
    kHistoryIndexKey,
    kLogIndexKey,
    kCallTracesKey,
    kTxLookupKey,
    kTriggersStageKey,
    kFinishKey,
};

static const ExecutionPipeline::StageNames kStagesUnwindOrder{
    kFinishKey,
    kTriggersStageKey,
    kTxLookupKey,
    kCallTracesKey,
    kLogIndexKey,
    kHistoryIndexKey,
    kHashStateKey,
    kIntermediateHashesKey,  // Needs to happen after unwinding HashState
    kExecutionKey,
    kSendersKey,
    kBlockBodiesKey,
    kBlockHashesKey,
    kHeadersKey,
};

ExecutionPipeline::StageNames ExecutionPipeline::stages_forward_order() {
    return kStagesForwardOrder;
}

ExecutionPipeline::StageNames ExecutionPipeline::stages_unwind_order() {
    return kStagesUnwindOrder;
}

ExecutionPipeline::ExecutionPipeline(
    db::DataModelFactory data_model_factory,
    std::optional<TimerFactory> log_timer_factory,
    const StageContainerFactory& stages_factory)
    : data_model_factory_{std::move(data_model_factory)},
      log_timer_factory_{std::move(log_timer_factory)},
      sync_context_{std::make_unique<SyncContext>()},
      stages_{stages_factory(*sync_context_)},
      current_stage_{stages_.end()},
      stages_forward_order_{kStagesForwardOrder},
      stages_unwind_order_{kStagesUnwindOrder} {}

BlockNum ExecutionPipeline::head_header_number() const {
    return head_header_block_num_;
}

Hash ExecutionPipeline::head_header_hash() const {
    return head_header_hash_;
}

std::optional<BlockNum> ExecutionPipeline::unwind_point() {
    return sync_context_->unwind_point;
}

std::optional<Hash> ExecutionPipeline::bad_block() {
    return sync_context_->bad_block_hash;
}

bool ExecutionPipeline::stop() {
    bool stopped{true};
    for (const auto& [_, stage] : stages_) {
        if (!stage->is_stopping()) {
            stopped &= stage->stop();
        }
    }
    return stopped;
}

datastore::StageScheduler& ExecutionPipeline::stage_scheduler() const {
    return *dynamic_cast<datastore::StageScheduler*>(stages_.at(kTriggersStageKey).get());
}

Stage::Result ExecutionPipeline::forward(db::RWTxn& cycle_txn, BlockNum target_block_num) {
    using std::to_string;
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();

    sync_context_->target_block_num = target_block_num;
    SILK_INFO_M("ExecutionPipeline") << "Forward start";

    try {
        Stage::Result result = Stage::Result::kSuccess;

        // We'll check if we're forced to start/stop at any particular stage/block_num for debugging purposes
        auto start_stage_name{Environment::get_start_at_stage()};
        const auto stop_stage_name{Environment::get_stop_before_stage()};
        const auto stop_at_block = Environment::get_stop_at_block();
        if (stop_at_block) {
            sync_context_->target_block_num = *stop_at_block;
        }

        current_stages_count_ = stages_forward_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_forward_order_) {
            // retrieve current stage
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");
            }
            ++current_stage_number_;
            const auto& current_stage_name = current_stage_->first;
            current_stage_->second->set_log_prefix(get_log_prefix(current_stage_name));

            // Check if we have to start at specific stage due to environment variable
            if (start_stage_name) {
                // Stage is not the start one, skip it and continue
                if (start_stage_name != stage_id) {
                    log::Info("Skipping " + std::string(stage_id) + "...", {"START_AT_STAGE", *start_stage_name, "hit", "true"});
                    continue;
                }
                // Start stage just found, avoid skipping next stages
                start_stage_name = std::nullopt;
            }

            // Check if we have to stop due to environment variable
            if (stop_stage_name && stop_stage_name == stage_id) {
                log::Warning("Stopping ...", {"STOP_BEFORE_STAGE", *stop_stage_name, "hit", "true"});
                result = Stage::Result::kStoppedByEnv;
                break;
            }

            if (log_timer) {
                log_timer->reset();  // Resets the interval for next log line from now
            }

            // forward
            const auto stage_result = current_stage_->second->forward(cycle_txn);

            if (stage_result != Stage::Result::kSuccess) { /* clang-format off */
                const auto result_description = std::string(magic_enum::enum_name<Stage::Result>(stage_result));
                SILK_ERROR_M(get_log_prefix(current_stage_name), {"op", "Forward", "failure", result_description});
                return stage_result;
            } /* clang-format on */

            const auto stage_head_number = read_stage_progress(cycle_txn, current_stage_name.data());
            if (!stop_at_block && stage_head_number != target_block_num) {
                SILK_ERROR_M(get_log_prefix(current_stage_name),
                             {"op", "Forward", "target", to_string(target_block_num), "reached", to_string(stage_head_number)});
                throw std::logic_error("stage returned success with an block_num different from target=" +
                                       to_string(target_block_num) + " reached=" + to_string(stage_head_number));
            }

            const auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                SILK_INFO_M(get_log_prefix(current_stage_name), {"op", "Forward", "done", StopWatch::format(stage_duration)});
            }
        }

        db::DataModel data_model = data_model_factory_(cycle_txn);
        const auto [head_header, head_header_hash] = data_model.read_head_header_and_hash();
        head_header_hash_ = head_header_hash.value_or(Hash{});
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_block_num_ = head_header->number;
        if (!stop_at_block && head_header_block_num_ != target_block_num) {
            throw std::logic_error("Sync pipeline: head header not at target block_num " + to_string(target_block_num) +
                                   ", head_header_block_num= " + to_string(head_header_block_num_));
        }

        SILK_INFO_M("ExecutionPipeline") << "Forward done";

        if (stop_at_block && stop_at_block <= head_header_block_num_) {
            SILK_WARN_M("ExecutionPipeline") << "Interrupted by STOP_AT_BLOCK at block " + to_string(*stop_at_block);
            return Stage::Result::kStoppedByEnv;
        }

        return result;
    } catch (const std::exception& ex) {
        SILK_ERROR_M("ExecutionPipeline") << get_log_prefix("unknown") << " Forward exception " << ex.what();
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result ExecutionPipeline::unwind(db::RWTxn& cycle_txn, BlockNum unwind_point) {
    using std::to_string;
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();
    SILK_INFO_M("ExecutionPipeline") << "Unwind start";

    try {
        sync_context_->unwind_point = unwind_point;

        // Loop at stages in unwind order
        current_stages_count_ = stages_unwind_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_unwind_order_) {
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");
            }
            ++current_stage_number_;
            const auto& current_stage_name = current_stage_->first;
            current_stage_->second->set_log_prefix(get_log_prefix(current_stage_name));

            if (log_timer) {
                log_timer->reset();  // Resets the interval for next log line from now
            }

            // Do unwind on current stage
            const auto stage_result = current_stage_->second->unwind(cycle_txn);
            if (stage_result != Stage::Result::kSuccess) {
                auto result_description = std::string(magic_enum::enum_name<Stage::Result>(stage_result));
                log::Error(get_log_prefix(current_stage_name), {"op", "Unwind", "returned", result_description});
                SILK_ERROR_M("ExecutionPipeline") << "Unwind interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            }

            // Log performances
            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                log::Info(get_log_prefix(current_stage_name), {"op", "Unwind", "done", StopWatch::format(stage_duration)});
            }
        }

        db::DataModel data_model = data_model_factory_(cycle_txn);
        const auto [head_header, head_header_hash] = data_model.read_head_header_and_hash();
        head_header_hash_ = head_header_hash.value_or(Hash{});
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_block_num_ = head_header->number;
        if (head_header_block_num_ != unwind_point) {
            throw std::logic_error("Sync pipeline: head header not at unwind point " + to_string(unwind_point) +
                                   ", head_header_block_num=" + to_string(head_header_block_num_));
        }

        // Clear context
        std::swap(sync_context_->unwind_point, sync_context_->previous_unwind_point);
        sync_context_->unwind_point.reset();
        sync_context_->bad_block_hash.reset();

        SILK_INFO_M("ExecutionPipeline") << "Unwind done";
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        SILK_ERROR_M("ExecutionPipeline") << get_log_prefix("unknown") << " Unwind exception " << ex.what();
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result ExecutionPipeline::prune(db::RWTxn& cycle_txn) {
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();
    SILK_INFO_M("ExecutionPipeline") << "Prune start";

    try {
        current_stages_count_ = stages_forward_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_unwind_order_) {
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                // Should not happen
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");
            }
            ++current_stage_number_;
            const auto& current_stage_name = current_stage_->first;
            current_stage_->second->set_log_prefix(get_log_prefix(current_stage_name));

            if (log_timer) {
                log_timer->reset();  // Resets the interval for next log line from now
            }

            const auto stage_result{current_stage_->second->prune(cycle_txn)};
            if (stage_result != Stage::Result::kSuccess) {
                log::Error(get_log_prefix(current_stage_name), {"op", "Prune", "returned",
                                                                std::string(magic_enum::enum_name<Stage::Result>(stage_result))});
                SILK_ERROR_M("ExecutionPipeline") << "Prune interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                log::Info(get_log_prefix(current_stage_name), {"op", "Prune", "done", StopWatch::format(stage_duration)});
            }
        }

        db::DataModel data_model = data_model_factory_(cycle_txn);
        const auto [head_header, head_header_hash] = data_model.read_head_header_and_hash();
        head_header_hash_ = head_header_hash.value_or(Hash{});
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_block_num_ = head_header->number;

        SILK_INFO_M("ExecutionPipeline") << "Prune done";
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        SILK_ERROR_M("ExecutionPipeline") << get_log_prefix("unknown") << " Prune exception " << ex.what();
        return Stage::Result::kUnexpectedError;
    }
}

std::string ExecutionPipeline::get_log_prefix(const std::string_view& stage_name) const {
    return absl::StrFormat("[%u/%u %s]",
                           current_stage_number_,
                           current_stages_count_,
                           stage_name);
}

std::shared_ptr<Timer> ExecutionPipeline::make_log_timer() {
    if (log_timer_factory_) {
        return log_timer_factory_.value()([this]() { return log_timer_expired(); });
    }
    return {};
}

bool ExecutionPipeline::log_timer_expired() {
    const auto current_stage_name =
        (current_stage_ != stages_.end())
            ? current_stage_->first
            : "unknown";
    if (is_stopping()) {
        log::Info(get_log_prefix(current_stage_name)) << "stopping ...";
        return false;
    }
    log::Info(get_log_prefix(current_stage_name), current_stage_->second->get_log_progress());
    return true;
}

}  // namespace silkworm::stagedsync
