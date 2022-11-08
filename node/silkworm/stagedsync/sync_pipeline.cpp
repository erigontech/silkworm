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

#include "sync_pipeline.hpp"

#include <boost/format.hpp>

#include <silkworm/stagedsync/stage_blockhashes.hpp>
#include <silkworm/stagedsync/stage_bodies.hpp>
#include <silkworm/stagedsync/stage_execution.hpp>
#include <silkworm/stagedsync/stage_finish.hpp>
#include <silkworm/stagedsync/stage_hashstate.hpp>
#include <silkworm/stagedsync/stage_headers.hpp>
#include <silkworm/stagedsync/stage_history_index.hpp>
#include <silkworm/stagedsync/stage_interhashes.hpp>
#include <silkworm/stagedsync/stage_log_index.hpp>
#include <silkworm/stagedsync/stage_senders.hpp>
#include <silkworm/stagedsync/stage_tx_lookup.hpp>

namespace silkworm::stagedsync {

class SyncPipeline::LogTimer : public Timer {
  public:
    LogTimer(SyncPipeline* pipeline)
        : Timer(
              pipeline->node_settings_->asio_context,
              pipeline->node_settings_->sync_loop_log_interval_seconds * 1'000,
              [pipeline]() -> bool {
                  if (pipeline->is_stopping()) {
                      log::Info(pipeline->get_log_prefix()) << "stopping ...";
                      return false;
                  }
                  log::Info(pipeline->get_log_prefix(), pipeline->current_stage_->second->get_log_progress());
                  return true;
              },
              true)
    {
        start();
    }

    ~LogTimer() {
        stop();
    }
};

SyncPipeline::SyncPipeline(silkworm::NodeSettings* node_settings)
    : node_settings_{node_settings},
      sync_context_{std::make_unique<SyncContext>()} {

    load_stages();
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

void SyncPipeline::load_stages() {
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
                                    db::stages::kHashStateKey,           // Needs to happen before unwinding Execution
                                    db::stages::kIntermediateHashesKey,  // Needs to happen after unwinding HashState
                                    db::stages::kExecutionKey,
                                    db::stages::kSendersKey,
                                    db::stages::kBlockBodiesKey,
                                    db::stages::kBlockHashesKey,  // Decanonify block hashes
                                    db::stages::kHeadersKey,
                                });
}

bool SyncPipeline::stop() {
    bool stopped{true};
    for (const auto& [_, stage] : stages_) {
        if (!stage->is_stopping()) {
            stopped &= stage->stop();
        }
    }
    return stopped;
}

Stage::Result SyncPipeline::forward(db::RWTxn& cycle_txn, Hash target_header) {
    StopWatch stages_stop_watch(true);
    LogTimer log_timer{this};

    // todo: use target_header

    try {
        // Force to stop at any particular stage ?
        const std::string env_stop_before_stage{"STOP_BEFORE_STAGE"};
        const char* stop_stage_name{std::getenv(env_stop_before_stage.c_str())};

        current_stages_count_ = stages_forward_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_forward_order_) {
            // retrieve current stage
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");  // Should not happen
            }
            ++current_stage_number_;
            current_stage_->second->set_log_prefix(get_log_prefix());

            // check if we have to stop due to environment variable
            if (stop_stage_name && iequals(stop_stage_name, stage_id)) {
                log::Warning("Stopping ...", {"STOP_BEFORE_STAGE", stop_stage_name, "hit", "true"});
                return Stage::Result::kStoppedByEnv;
            }

            log_timer.reset();  // Resets the interval for next log line from now

            // forward
            const auto stage_result = current_stage_->second->forward(cycle_txn);

            if (stage_result != Stage::Result::kSuccess) {
                log::Error(get_log_prefix(),
                           {"op", "Forward",
                            "returned", std::string(magic_enum::enum_name<Stage::Result>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Forward",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result SyncPipeline::unwind(db::RWTxn& cycle_txn) {
    StopWatch stages_stop_watch(true);
    LogTimer log_timer{this};

    try {
        current_stages_count_ = stages_unwind_order_.size();
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
            const auto stage_result{current_stage_->second->unwind(cycle_txn)};
            if (stage_result != Stage::Result::kSuccess) {
                log::Error(get_log_prefix(),
                           {"op", "Unwind",
                            "returned", std::string(magic_enum::enum_name<Stage::Result>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Unwind",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

Stage::Result SyncPipeline::prune(db::RWTxn& cycle_txn) {
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
                log::Error(get_log_prefix(),
                           {"op", "Prune",
                            "returned", std::string(magic_enum::enum_name<Stage::Result>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Prune",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? Stage::Result::kAborted : Stage::Result::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return Stage::Result::kUnexpectedError;
    }
}

std::string SyncPipeline::get_log_prefix() const {
    static std::string log_prefix_fmt{"[%u/%u %s]"};
    return boost::str(boost::format(log_prefix_fmt) %
                      current_stage_number_ %
                      current_stages_count_ %
                      current_stage_->first);
}

}  // namespace silkworm::stagedsync
