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

#include "sync_loop.hpp"

#include <boost/format.hpp>

#include <silkworm/stagedsync/stage_blockhashes.hpp>
#include <silkworm/stagedsync/stage_execution.hpp>
#include <silkworm/stagedsync/stage_finish.hpp>
#include <silkworm/stagedsync/stage_hashstate.hpp>
#include <silkworm/stagedsync/stage_history_index.hpp>
#include <silkworm/stagedsync/stage_interhashes.hpp>
#include <silkworm/stagedsync/stage_log_index.hpp>
#include <silkworm/stagedsync/stage_senders.hpp>
#include <silkworm/stagedsync/stage_tx_lookup.hpp>

namespace silkworm::stagedsync {

void SyncLoop::load_stages() {
    /*
     * Stages from Erigon -> Silkworm
     *  1 StageHeaders ->  Downloader ?
     *  2 StageCumulativeIndex -> Downloader ?
     *  3 StageBlockHashes -> stagedsync::BlockHashes
     *  4 StageBodies -> Downloader ?
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
                                    db::stages::kBlockHashesKey,  // Decanonify block hashes
                                });
}

void SyncLoop::stop(bool wait) {
    for (const auto& [_, stage] : stages_) {
        if (!stage->is_stopping()) {
            stage->stop();
        }
    }
    Worker::stop(wait);
}

void SyncLoop::work() {
    Timer log_timer(
        node_settings_->asio_context, node_settings_->sync_loop_log_interval_seconds * 1'000,
        [&]() -> bool {
            if (is_stopping()) {
                log::Info(get_log_prefix()) << "stopping ...";
                return false;
            }
            log::Info(get_log_prefix(), current_stage_->second->get_log_progress());
            return true;
        },
        true);

    try {
        log::Info() << "SyncLoop started";

        // Open a temporary transaction to see if we have an uncompleted Unwind from previous
        // runs.
        {
            auto txn{chaindata_env_->start_write()};
            db::Cursor source(txn, db::table::kSyncStageProgress);
            mdbx::slice key(db::stages::kUnwindKey);
            auto data{source.find(key, /*throw_notfound=*/false)};
            if (data && data.value.size() == sizeof(BlockNum)) {
                sync_context_->unwind_to = endian::load_big_u64(db::from_slice(data.value).data());
            }
        }

        sync_context_->is_first_cycle = true;
        std::unique_ptr<db::RWTxn> cycle_txn{nullptr};
        mdbx::txn_managed external_txn;

        StopWatch cycle_stop_watch;

        while (!is_stopping()) {
            cycle_stop_watch.start(/*with_reset=*/true);

            bool cycle_in_one_tx{!sync_context_->is_first_cycle};

            {
                auto ro_tx{chaindata_env_->start_read()};
                auto from{db::stages::read_stage_progress(ro_tx, db::stages::kFinishKey)};
                auto to{db::stages::read_stage_progress(ro_tx, db::stages::kHeadersKey)};
                if (to >= from && to - from > 4096) {
                    cycle_in_one_tx = false;
                }
            }

            if (cycle_in_one_tx) {
                // A single commit at the end of the cycle
                external_txn = chaindata_env_->start_write();
                cycle_txn = std::make_unique<db::RWTxn>(external_txn);
                log::Trace("SyncLoop", {"db transactions", "per cycle"});
            } else {
                // Single stages will commit
                cycle_txn = std::make_unique<db::RWTxn>(*chaindata_env_);
                log::Trace("SyncLoop", {"db transactions", "per stage"});
            }

            // Run forward
            if (sync_context_->unwind_to.has_value() == false) {
                bool should_end_loop{false};
                const auto forward_result{run_cycle_forward(*cycle_txn, log_timer)};
                switch (forward_result) {
                    case StageResult::kInvalidBlock:
                    case StageResult::kWrongStateRoot:
                        break;  // Do nothing. Unwind is triggered afterwards
                    case StageResult::kStoppedByEnv:
                        should_end_loop = true;
                        break;
                    default:
                        throw StageError(forward_result);
                }
                if (should_end_loop) break;
            }

            // Run unwind if required
            if (sync_context_->unwind_to.has_value()) {
                // Need to persist unwind point (in case of user stop)
                db::stages::write_stage_progress(*cycle_txn, db::stages::kUnwindKey, sync_context_->unwind_to.value());

                // Run unwind
                log::Warning("Unwinding", {"to", std::to_string(sync_context_->unwind_to.value())});
                const auto unwind_result{run_cycle_unwind(*cycle_txn, log_timer)};
                success_or_throw(unwind_result);  // Must be successful: no recovery from bad unwinding

                // Erase unwind key from progress table
                db::Cursor progress_table(*cycle_txn, db::table::kSyncStageProgress);
                mdbx::slice key(db::stages::kUnwindKey);
                (void)progress_table.erase(key);

                // Clear context
                std::swap(sync_context_->unwind_to, sync_context_->previous_unwind_to);
                sync_context_->unwind_to.reset();
                sync_context_->bad_block_hash.reset();
            }

            // Eventually run prune (should not fail)
            success_or_throw(run_cycle_prune(*cycle_txn, log_timer));

            if (cycle_in_one_tx) {
                external_txn.commit();
            } else {
                cycle_txn->commit();
            }

            cycle_txn.reset();
            sync_context_->is_first_cycle = false;

            auto [_, cycle_duration] = cycle_stop_watch.lap();
            log::Info("Cycle completed", {"elapsed", StopWatch::format(cycle_duration)});
            throttle_next_cycle(cycle_duration);
        }

    } catch (const StageError& ex) {
        log::Error("SyncLoop",
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
    } catch (const mdbx::exception& ex) {
        log::Error("SyncLoop",
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
    } catch (const std::exception& ex) {
        log::Error("SyncLoop",
                   {"function", std::string(__FUNCTION__), "exception", std::string(ex.what())});
    } catch (...) {
        log::Error("SyncLoop",
                   {"function", std::string(__FUNCTION__), "exception", "undefined"});
    }

    log_timer.stop();
    log::Info() << "SyncLoop terminated";
}

StageResult SyncLoop::run_cycle_forward(db::RWTxn& cycle_txn, Timer& log_timer) {
    StopWatch stages_stop_watch(true);
    try {
        // Force to stop at any particular stage ?
        // Same as in Erigon
        const std::string env_stop_before_stage{"STOP_BEFORE_STAGE"};
        const char* stop_stage_name{std::getenv(env_stop_before_stage.c_str())};

        current_stages_count_ = stages_forward_order_.size();
        current_stage_number_ = 0;
        for (auto& stage_id : stages_forward_order_) {
            current_stage_ = stages_.find(stage_id);
            if (current_stage_ == stages_.end()) {
                // Should not happen
                throw std::runtime_error("Stage " + std::string(stage_id) + " requested but not implemented");
            }
            ++current_stage_number_;
            current_stage_->second->set_log_prefix(get_log_prefix());

            // Check if we have to stop due to environment variable
            if (stop_stage_name && !iequals(stop_stage_name, stage_id)) {
                stop();
                log::Warning("Stopping ...", {"STOP_BEFORE_STAGE", stop_stage_name, "hit", "true"});
                return StageResult::kStoppedByEnv;
            }

            log_timer.reset();  // Resets the interval for next log line from now
            const auto stage_result{current_stage_->second->forward(cycle_txn)};
            if (stage_result != StageResult::kSuccess) {
                log::Error(get_log_prefix(),
                           {"op", "Forward",
                            "returned", std::string(magic_enum::enum_name<StageResult>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Forward",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

StageResult SyncLoop::run_cycle_unwind(db::RWTxn& cycle_txn, Timer& log_timer) {
    StopWatch stages_stop_watch(true);
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
            if (stage_result != StageResult::kSuccess) {
                log::Error(get_log_prefix(),
                           {"op", "Unwind",
                            "returned", std::string(magic_enum::enum_name<StageResult>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Unwind",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

StageResult SyncLoop::run_cycle_prune(db::RWTxn& cycle_txn, Timer& log_timer) {
    StopWatch stages_stop_watch(true);
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
            if (stage_result != StageResult::kSuccess) {
                log::Error(get_log_prefix(),
                           {"op", "Prune",
                            "returned", std::string(magic_enum::enum_name<StageResult>(stage_result))});
                return stage_result;
            }

            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(),
                          {"op", "Prune",
                           "done", StopWatch::format(stage_duration)});
            }
        }

        return is_stopping() ? StageResult::kAborted : StageResult::kSuccess;

    } catch (const std::exception& ex) {
        log::Error(get_log_prefix(), {"exception", std::string(ex.what())});
        return StageResult::kUnexpectedError;
    }
}

void SyncLoop::throttle_next_cycle(const StopWatch::Duration& cycle_duration) {
    if (is_stopping() || !node_settings_->sync_loop_throttle_seconds) {
        return;
    }

    auto min_duration = std::chrono::duration_cast<StopWatch::Duration>(
        std::chrono::seconds(node_settings_->sync_loop_throttle_seconds));
    if (min_duration <= cycle_duration) {
        return;
    }

    auto wait_duration{min_duration - cycle_duration};
    log::Info() << "Next cycle starts in " << StopWatch::format(wait_duration);
    auto next_start_time = std::chrono::high_resolution_clock::now() + wait_duration;
    while (std::chrono::high_resolution_clock::now() < next_start_time) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (is_stopping()) {
            break;
        }
    }
}
std::string SyncLoop::get_log_prefix() const {
    static std::string log_prefix_fmt{"[%u/%u %s]"};
    return boost::str(boost::format(log_prefix_fmt) %
                      current_stage_number_ %
                      current_stages_count_ %
                      current_stage_->first);
}

}  // namespace silkworm::stagedsync
