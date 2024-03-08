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

#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/environment.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
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
#include <silkworm/node/stagedsync/stages/stage_tx_lookup.hpp>

namespace silkworm::stagedsync {

#if defined(NDEBUG)
static const std::chrono::milliseconds kStageDurationThresholdForLog{10};
#else
static const std::chrono::milliseconds kStageDurationThresholdForLog{0};
#endif

class ExecutionPipeline::LogTimer : public Timer {
    ExecutionPipeline* pipeline_;

  public:
    LogTimer(const boost::asio::any_io_executor& executor, ExecutionPipeline* pipeline, uint32_t interval_seconds)
        : Timer{
              executor,
              interval_seconds * 1'000,
              [this] { return expired(); },
              /*.auto_start=*/true},
          pipeline_{pipeline} {}

    bool expired() {
        if (pipeline_->is_stopping()) {
            log::Info(pipeline_->get_log_prefix()) << "stopping ...";
            return false;
        }
        log::Info(pipeline_->get_log_prefix(), pipeline_->current_stage_->second->get_log_progress());
        return true;
    }
};

std::unique_ptr<ExecutionPipeline::LogTimer> ExecutionPipeline::make_log_timer() {
    return std::make_unique<LogTimer>(
        this->node_settings_->asio_context.get_executor(),
        this,
        this->node_settings_->sync_loop_log_interval_seconds);
}

ExecutionPipeline::ExecutionPipeline(silkworm::NodeSettings* node_settings)
    : node_settings_{node_settings},
      sync_context_{std::make_unique<SyncContext>()} {
    load_stages();
}

BlockNum ExecutionPipeline::head_header_number() const {
    return head_header_number_;
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

/*
 * Stages from Erigon -> Silkworm
 *  1 StageHeaders ->  stagedsync::HeadersStage
 *  2 StageBodies -> stagedsync::BodiesStage
 *  3 StageBlockHashes -> stagedsync::BlockHashes
 *  4 StageSenders -> stagedsync::Senders
 *  5 StageExecution -> stagedsync::Execution
 *  6 StageHashState -> stagedsync::HashState
 *  7 StageInterHashes -> stagedsync::InterHashes
 *  8 StageIndexes -> stagedsync::HistoryIndex
 *  9 StageLogIndex -> stagedsync::LogIndex
 * 10 StageCallTraces -> stagedsync::CallTraceIndex
 * 11 StageTxLookup -> stagedsync::TxLookup
 * 12 StageFinish -> stagedsync::Finish
 */

void ExecutionPipeline::load_stages() {
    stages_.emplace(db::stages::kHeadersKey,
                    std::make_unique<stagedsync::HeadersStage>(sync_context_.get()));
    stages_.emplace(db::stages::kBlockBodiesKey,
                    std::make_unique<stagedsync::BodiesStage>(sync_context_.get(), *node_settings_->chain_config));
    stages_.emplace(db::stages::kBlockHashesKey,
                    std::make_unique<stagedsync::BlockHashes>(sync_context_.get(), node_settings_->etl()));
    stages_.emplace(db::stages::kSendersKey,
                    std::make_unique<stagedsync::Senders>(sync_context_.get(), *node_settings_->chain_config, node_settings_->batch_size, node_settings_->etl(), node_settings_->prune_mode.senders()));
    stages_.emplace(db::stages::kExecutionKey,
                    std::make_unique<stagedsync::Execution>(sync_context_.get(), *node_settings_->chain_config, node_settings_->batch_size, node_settings_->prune_mode));
    stages_.emplace(db::stages::kHashStateKey,
                    std::make_unique<stagedsync::HashState>(sync_context_.get(), node_settings_->etl()));
    stages_.emplace(db::stages::kIntermediateHashesKey,
                    std::make_unique<stagedsync::InterHashes>(sync_context_.get(), node_settings_->etl()));
    stages_.emplace(db::stages::kHistoryIndexKey,
                    std::make_unique<stagedsync::HistoryIndex>(sync_context_.get(), node_settings_->batch_size, node_settings_->etl(), node_settings_->prune_mode.history()));
    stages_.emplace(db::stages::kLogIndexKey,
                    std::make_unique<stagedsync::LogIndex>(sync_context_.get(), node_settings_->batch_size, node_settings_->etl(), node_settings_->prune_mode.history()));
    stages_.emplace(db::stages::kCallTracesKey,
                    std::make_unique<stagedsync::CallTraceIndex>(sync_context_.get(), node_settings_->batch_size, node_settings_->etl(), node_settings_->prune_mode.call_traces()));
    stages_.emplace(db::stages::kTxLookupKey,
                    std::make_unique<stagedsync::TxLookup>(sync_context_.get(), node_settings_->etl(), node_settings_->prune_mode.tx_index()));
    stages_.emplace(db::stages::kFinishKey,
                    std::make_unique<stagedsync::Finish>(sync_context_.get(), node_settings_->build_info));
    current_stage_ = stages_.begin();

    stages_forward_order_.insert(stages_forward_order_.begin(),
                                 {
                                     db::stages::kHeadersKey,
                                     db::stages::kBlockHashesKey,
                                     db::stages::kBlockBodiesKey,
                                     db::stages::kSendersKey,
                                     db::stages::kExecutionKey,
                                     db::stages::kHashStateKey,
                                     db::stages::kIntermediateHashesKey,
                                     db::stages::kHistoryIndexKey,
                                     db::stages::kLogIndexKey,
                                     db::stages::kCallTracesKey,
                                     db::stages::kTxLookupKey,
                                     db::stages::kFinishKey,
                                 });

    stages_unwind_order_.insert(stages_unwind_order_.begin(),
                                {
                                    db::stages::kFinishKey,
                                    db::stages::kTxLookupKey,
                                    db::stages::kCallTracesKey,
                                    db::stages::kLogIndexKey,
                                    db::stages::kHistoryIndexKey,
                                    db::stages::kHashStateKey,
                                    db::stages::kIntermediateHashesKey,  // Needs to happen after unwinding HashState
                                    db::stages::kExecutionKey,
                                    db::stages::kSendersKey,
                                    db::stages::kBlockBodiesKey,
                                    db::stages::kBlockHashesKey,  // De-canonify block hashes
                                    db::stages::kHeadersKey,
                                });
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

Stage::Result ExecutionPipeline::forward(db::RWTxn& cycle_txn, BlockNum target_height) {
    using std::to_string;
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();

    sync_context_->target_height = target_height;
    log::Info("ExecutionPipeline") << "Forward start";

    try {
        Stage::Result result = Stage::Result::kSuccess;

        // We'll check if we're forced to start/stop at any particular stage/height for debugging purposes
        auto start_stage_name{Environment::get_start_at_stage()};
        const auto stop_stage_name{Environment::get_stop_before_stage()};
        const auto stop_at_block = Environment::get_stop_at_block();

        current_stages_count_ = stages_forward_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_forward_order_) {
            // retrieve current stage
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");
            }
            ++current_stage_number_;
            current_stage_->second->set_log_prefix(get_log_prefix());

            // Check if we have to start at specific stage due to environment variable
            if (start_stage_name) {
                // Stage is not the start one, skip it and continue
                if (start_stage_name != stage_id) {
                    log::Info("Skipping " + std::string(stage_id) + "...", {"START_AT_STAGE", *start_stage_name, "hit", "true"});
                    continue;
                } else {
                    // Start stage just found, avoid skipping next stages
                    start_stage_name = std::nullopt;
                }
            }

            // Check if we have to stop due to environment variable
            if (stop_stage_name && stop_stage_name == stage_id) {
                log::Warning("Stopping ...", {"STOP_BEFORE_STAGE", *stop_stage_name, "hit", "true"});
                result = Stage::Result::kStoppedByEnv;
                break;
            }

            log_timer->reset();  // Resets the interval for next log line from now

            // forward
            const auto stage_result = current_stage_->second->forward(cycle_txn);

            if (stage_result != Stage::Result::kSuccess) { /* clang-format off */
                auto result_description = std::string(magic_enum::enum_name<Stage::Result>(stage_result));
                log::Error(get_log_prefix(), {"op", "Forward", "returned", result_description});
                log::Error("ExecPipeline") << "Forward interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            } /* clang-format on */

            auto stage_head_number = db::stages::read_stage_progress(cycle_txn, current_stage_->first);
            if (!stop_at_block && stage_head_number != target_height) {
                throw std::logic_error("Sync pipeline: stage returned success with an height different from target=" +
                                       to_string(target_height) + " reached= " + to_string(stage_head_number));
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                log::Info(get_log_prefix(), {"op", "Forward", "done", StopWatch::format(stage_duration)});
            }
        }

        head_header_hash_ = db::read_head_header_hash(cycle_txn).value_or(Hash{});
        const auto head_header = db::DataModel(cycle_txn).read_header(head_header_hash_);
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_number_ = head_header->number;
        if (head_header_number_ != target_height) {
            throw std::logic_error("Sync pipeline: head header not at target height " + to_string(target_height) +
                                   ", head_header_height= " + to_string(head_header_number_));
        }

        log::Info("ExecutionPipeline") << "Forward done";

        if (stop_at_block && stop_at_block <= head_header_number_) return Stage::Result::kStoppedByEnv;

        return result;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        log::Error("ExecPipeline") << "Forward aborted due to exception: " << ex.what();
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result ExecutionPipeline::unwind(db::RWTxn& cycle_txn, BlockNum unwind_point) {
    using std::to_string;
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();
    log::Info("ExecutionPipeline") << "Unwind start";

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
            current_stage_->second->set_log_prefix(get_log_prefix());
            log_timer->reset();  // Resets the interval for next log line from now

            // Do unwind on current stage
            const auto stage_result = current_stage_->second->unwind(cycle_txn);
            if (stage_result != Stage::Result::kSuccess) {
                auto result_description = std::string(magic_enum::enum_name<Stage::Result>(stage_result));
                log::Error(get_log_prefix(), {"op", "Unwind", "returned", result_description});
                log::Error("ExecPipeline") << "Unwind interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            }

            // Log performances
            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                log::Info(get_log_prefix(), {"op", "Unwind", "done", StopWatch::format(stage_duration)});
            }
        }

        head_header_hash_ = db::read_head_header_hash(cycle_txn).value_or(Hash{});
        const auto head_header = db::DataModel(cycle_txn).read_header(head_header_hash_);
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_number_ = head_header->number;
        if (head_header_number_ != unwind_point) {
            throw std::logic_error("Sync pipeline: head header not at unwind point " + to_string(unwind_point) +
                                   ", head_header_height=" + to_string(head_header_number_));
        }

        // Clear context
        std::swap(sync_context_->unwind_point, sync_context_->previous_unwind_point);
        sync_context_->unwind_point.reset();
        sync_context_->bad_block_hash.reset();

        log::Info("ExecutionPipeline") << "Unwind done";
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error("ExecPipeline") << "Unwind aborted due to exception: " << ex.what();
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result ExecutionPipeline::prune(db::RWTxn& cycle_txn) {
    StopWatch stages_stop_watch(true);
    auto log_timer = make_log_timer();
    log::Info("ExecutionPipeline") << "Prune start";

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
            current_stage_->second->set_log_prefix(get_log_prefix());

            log_timer->reset();  // Resets the interval for next log line from now
            const auto stage_result{current_stage_->second->prune(cycle_txn)};
            if (stage_result != Stage::Result::kSuccess) {
                log::Error(get_log_prefix(), {"op", "Prune", "returned",
                                              std::string(magic_enum::enum_name<Stage::Result>(stage_result))});
                log::Error("ExecPipeline") << "Prune interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > kStageDurationThresholdForLog) {
                log::Info(get_log_prefix(), {"op", "Prune", "done", StopWatch::format(stage_duration)});
            }
        }

        head_header_hash_ = db::read_head_header_hash(cycle_txn).value_or(Hash{});
        const auto head_header = db::DataModel(cycle_txn).read_header(head_header_hash_);
        ensure(head_header.has_value(), [&]() { return "Sync pipeline, missing head header hash " + to_hex(head_header_hash_); });
        head_header_number_ = head_header->number;

        log::Info("ExecutionPipeline") << "Prune done";
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

std::string ExecutionPipeline::get_log_prefix() const {
    return absl::StrFormat("[%u/%u %s]",
                           current_stage_number_,
                           current_stages_count_,
                           current_stage_->first);
}

}  // namespace silkworm::stagedsync
