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
    LogTimer(ExecutionPipeline* pipeline)
        : Timer{
              pipeline->node_settings_->asio_context.get_executor(),
              pipeline->node_settings_->sync_loop_log_interval_seconds * 1'000,
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
 *  2 StageCumulativeIndex -> TBD
 *  3 StageBlockHashes -> stagedsync::BlockHashes
 *  4 StageBodies -> stagedsync::BodiesStage
 *  5 StageIssuance -> TBD
 *  6 StageSenders -> stagedsync::Senders
 *  7 StageExecuteBlocks -> stagedsync::Execution
 *  8 StageTranspile -> TBD
 *  9 StageHashState -> stagedsync::HashState
 * 10 StageTrie -> stagedsync::InterHashes
 * 11 StageHistory -> stagedsync::HistoryIndex
 * 12 StageLogIndex -> stagedsync::LogIndex
 * 13 StageCallTraces -> TBD
 * 14 StageTxLookup -> stagedsync::TxLookup
 * 15 StageFinish -> stagedsync::Finish
 */

void ExecutionPipeline::load_stages() {
    stages_.emplace(db::stages::kHeadersKey,
                    std::make_unique<stagedsync::HeadersStage>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kBlockBodiesKey,
                    std::make_unique<stagedsync::BodiesStage>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kBlockHashesKey,
                    std::make_unique<stagedsync::BlockHashes>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kSendersKey,
                    std::make_unique<stagedsync::Senders>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kExecutionKey,
                    std::make_unique<stagedsync::Execution>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kHashStateKey,
                    std::make_unique<stagedsync::HashState>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kIntermediateHashesKey,
                    std::make_unique<stagedsync::InterHashes>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kHistoryIndexKey,
                    std::make_unique<stagedsync::HistoryIndex>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kLogIndexKey,
                    std::make_unique<stagedsync::LogIndex>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kTxLookupKey,
                    std::make_unique<stagedsync::TxLookup>(node_settings_, sync_context_.get()));
    stages_.emplace(db::stages::kFinishKey,
                    std::make_unique<stagedsync::Finish>(node_settings_, sync_context_.get()));
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
                                     db::stages::kTxLookupKey,
                                     db::stages::kFinishKey,
                                 });

    stages_unwind_order_.insert(stages_unwind_order_.begin(),
                                {
                                    db::stages::kFinishKey,
                                    db::stages::kTxLookupKey,
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
    LogTimer log_timer{this};

    sync_context_->target_height = target_height;
    log::Info("ExecPipeline") << "Forward start --------------------------";

    try {
        Stage::Result result = Stage::Result::kSuccess;

        // We'll check if we're forced to start/stop at any particular stage for debugging purposes
        auto start_stage_name{Environment::get_start_at_stage()};
        const auto stop_stage_name{Environment::get_stop_before_stage()};

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

            log_timer.reset();  // Resets the interval for next log line from now

            // forward
            const auto stage_result = current_stage_->second->forward(cycle_txn);

            if (stage_result != Stage::Result::kSuccess) { /* clang-format off */
                auto result_description = std::string(magic_enum::enum_name<Stage::Result>(stage_result));
                log::Error(get_log_prefix(), {"op", "Forward", "returned", result_description});
                log::Error("ExecPipeline") << "Forward interrupted due to stage " << current_stage_->first << " failure";
                return stage_result;
            } /* clang-format on */

            auto stage_head_number = db::stages::read_stage_progress(cycle_txn, current_stage_->first);
            if (stage_head_number != target_height) {
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
        ensure(head_header.has_value(), "Sync pipeline, missing head header hash " + to_hex(head_header_hash_));
        head_header_number_ = head_header->number;
        if (head_header_number_ != target_height) {
            throw std::logic_error("Sync pipeline: head header not at target height " + to_string(target_height) +
                                   ", head_header_height= " + to_string(head_header_number_));
        }

        log::Info("ExecPipeline") << "Forward done ---------------------------";

        const auto stop_at_block = Environment::get_stop_at_block();  // User can specify to stop at some block
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
    LogTimer log_timer{this};
    log::Info("ExecPipeline") << "Unwind start ---------------------------";

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
            log_timer.reset();  // Resets the interval for next log line from now

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
        ensure(head_header.has_value(), "Sync pipeline, missing head header hash " + to_hex(head_header_hash_));
        head_header_number_ = head_header->number;
        if (head_header_number_ != unwind_point) {
            throw std::logic_error("Sync pipeline: head header not at unwind point " + to_string(unwind_point) +
                                   ", head_header_height=" + to_string(head_header_number_));
        }

        // Clear context
        std::swap(sync_context_->unwind_point, sync_context_->previous_unwind_point);
        sync_context_->unwind_point.reset();
        sync_context_->bad_block_hash.reset();

        log::Info("ExecPipeline") << "Unwind done ----------------------------";
        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error("ExecPipeline") << "Unwind aborted due to exception: " << ex.what();
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result ExecutionPipeline::prune(db::RWTxn& cycle_txn) {
    StopWatch stages_stop_watch(true);
    LogTimer log_timer{this};

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

            log_timer.reset();  // Resets the interval for next log line from now
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
        ensure(head_header.has_value(), "Sync pipeline, missing head header hash " + to_hex(head_header_hash_));
        head_header_number_ = head_header->number;

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
