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

#include <silkworm/common/log.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

namespace silkworm::stagedysnc {

void SyncLoop::load_stages() { stages_.push_back(std::make_unique<stagedsync::BlockHashes>(node_settings_)); }

void SyncLoop::work() {
    log::Trace() << "Synchronization loop started";

    unsigned int counter{0};
    bool is_first_cycle{true};
    std::unique_ptr<db::RWTxn> cycle_txn{nullptr};
    mdbx::txn_managed external_txn;
    StopWatch stop_watch;

    while (!is_stopping()) {
        current_stage_ = 0;
        stop_watch.start(/*with_reset=*/true);

        // TODO we should get highest seen from header downloader but is not plugged in yet
        BlockNum highest_seen_header{13'000'000};
        bool cycle_in_one_tx{!is_first_cycle};

        {
            auto ro_tx{chaindata_env_->start_read()};
            auto origin{db::stages::read_stage_progress(ro_tx, db::stages::kHeadersKey)};
            if (highest_seen_header >= origin && highest_seen_header - origin < 8096) {
                cycle_in_one_tx = false;
            }
            auto previous_finish_progress{db::stages::read_stage_progress(ro_tx, db::stages::kFinishKey)};
            if (highest_seen_header >= previous_finish_progress &&
                highest_seen_header - previous_finish_progress < 8096) {
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

        while (current_stage_ < stages_.size()) {
            auto stage_result{stages_.at(current_stage_)->forward(*cycle_txn)};
            stagedsync::success_or_throw(stage_result);
            auto [_, stage_duration] = stop_watch.lap();
            log::Trace() << "Stage " << stages_.at(current_stage_)->name() << " done in "
                         << StopWatch::format(stage_duration);
            ++current_stage_;
        }

        // std::this_thread::sleep_for(std::chrono::seconds(3));
        // log::Info() << "Sync loop operations in progress";
        // if (++counter > 10) {
        //   throw std::runtime_error("Forced exception");
        // }

        if (cycle_in_one_tx) {
            external_txn.commit();
        } else {
            cycle_txn->commit();
        }
        cycle_txn.reset();
        is_first_cycle = false;

        auto [time_point, _] = stop_watch.lap();
        auto cycle_duration{stop_watch.since_start(time_point)};
        log::Info() << "Cycle completed in " << stop_watch.format(cycle_duration);

        if (node_settings_->sync_loop_throttle) {
            auto min_duration = std::chrono::duration_cast<StopWatch::Duration>(
                std::chrono::seconds(node_settings_->sync_loop_throttle));
            if (min_duration > cycle_duration) {
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
        }
    }

    log::Trace() << "Synchronization loop stopped";
}

}  // namespace silkworm::stagedysnc
