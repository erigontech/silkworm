/*
    Copyright 2021 The Silkworm Authors

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
#include <silkworm/stagedsync/stage_hashstate.hpp>
#include <silkworm/stagedsync/stage_senders.hpp>

namespace silkworm::stagedsync {

void SyncLoop::load_stages() {
    stages_.push_back(std::make_unique<stagedsync::BlockHashes>(node_settings_));
    stages_.push_back(std::make_unique<stagedsync::Senders>(node_settings_));
    stages_.push_back(std::make_unique<stagedsync::Execution>(node_settings_));
    stages_.push_back(std::make_unique<stagedsync::HashState>(node_settings_));
}

void SyncLoop::stop(bool wait) {
    for (const auto& stage : stages_) {
        if (!stage->is_stopping()) {
            stage->stop();
        }
    }
    Worker::stop(wait);
}

void SyncLoop::work() {
    log::Trace() << "Synchronization loop started";

    bool is_first_cycle{true};
    std::unique_ptr<db::RWTxn> cycle_txn{nullptr};
    mdbx::txn_managed external_txn;

    StopWatch cycle_stop_watch;
    Timer log_timer(
        node_settings_->asio_context, node_settings_->sync_loop_log_interval_seconds * 1'000,
        [&]() -> bool {
            if (is_stopping()) {
                log::Info(get_log_prefix()) << "stopping ...";
                return false;
            }
            log::Info(get_log_prefix(), stages_.at(current_stage_)->get_log_progress());
            return true;
        },
        true);

    while (!is_stopping()) {
        current_stage_ = 0;
        cycle_stop_watch.start(/*with_reset=*/true);

        // TODO we should get highest seen from header downloader but is not plugged in yet
        BlockNum highest_seen_header{14'000'000};
        bool cycle_in_one_tx{!is_first_cycle};

        {
            auto ro_tx{chaindata_env_->start_read()};
            auto origin{db::stages::read_stage_progress(ro_tx, db::stages::kHeadersKey)};
            if (highest_seen_header >= origin && highest_seen_header - origin > 8096) {
                cycle_in_one_tx = false;
            }
            auto previous_finish_progress{db::stages::read_stage_progress(ro_tx, db::stages::kFinishKey)};
            if (highest_seen_header >= previous_finish_progress &&
                highest_seen_header - previous_finish_progress > 8096) {
                cycle_in_one_tx = false;
            }
        }

        if (cycle_in_one_tx) {
            // A single commit at the end of the cycle
            external_txn = chaindata_env_->start_write();
            cycle_txn = std::make_unique<db::RWTxn>(external_txn);
        } else {
            // Single stages will commit
            cycle_txn = std::make_unique<db::RWTxn>(*chaindata_env_);
        }

        if (run_cycle(*cycle_txn, log_timer) != StageResult::kSuccess) {
            break;
        }

        if (cycle_in_one_tx) {
            external_txn.commit();
        } else {
            cycle_txn->commit();
        }

        cycle_txn.reset();
        is_first_cycle = false;

        auto [_, cycle_duration] = cycle_stop_watch.lap();
        log::Info("Cycle completed", {"elapsed", StopWatch::format(cycle_duration)});
        throttle_next_cycle(cycle_duration);

        break;  // TODO(Andrea) Remove
    }

    log_timer.stop();
    log::Info() << "Synchronization loop terminated";
}

StageResult SyncLoop::run_cycle(db::RWTxn& cycle_txn, Timer& log_timer) {
    StopWatch stages_stop_watch;
    (void)stages_stop_watch.start();
    try {
        for (; current_stage_ < stages_.size() && !is_stopping(); ++current_stage_) {
            auto& stage{stages_.at(current_stage_)};
            log_timer.reset();  // Resets the interval for next log line from now
            const auto stage_result{stage->forward(cycle_txn)};
            if (stage_result != StageResult::kSuccess) {
                log::Error(get_log_prefix(), {"return", std::string(magic_enum::enum_name<StageResult>(stage_result))});
                return stage_result;
            }
            auto [_, stage_duration] = stages_stop_watch.lap();
            if (stage_duration > std::chrono::milliseconds(10)) {
                log::Info(get_log_prefix(), {"done", StopWatch::format(stage_duration)});
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
    static std::string log_prefix_fmt{"Stage %u/%u : %s"};
    return boost::str(boost::format(log_prefix_fmt) % (current_stage_ + 1) % stages_.size() %
                      stages_.at(current_stage_)->name());
}

}  // namespace silkworm::stagedsync
