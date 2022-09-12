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

#pragma once

#include <map>

#include <silkworm/common/asio_timer.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/concurrency/worker.hpp>
#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

class SyncContext {
  public:
    SyncContext() = default;
    ~SyncContext() = default;

    // Not copyable nor movable
    SyncContext(const SyncContext&) = delete;
    SyncContext& operator=(const SyncContext&) = delete;

  private:
    std::optional<BlockNum> unwind_point_;
    std::optional<BlockNum> previous_unwind_point_;
    std::optional<evmc::bytes32> bad_block_hash_;
};

class SyncLoop final : public Worker {
  public:
    explicit SyncLoop(silkworm::NodeSettings* node_settings, mdbx::env* chaindata_env)
        : Worker("SyncLoop"), node_settings_{node_settings}, chaindata_env_{chaindata_env} {
        load_stages();
    };
    ~SyncLoop() override = default;

    void stop(bool wait = false) final;

  private:
    silkworm::NodeSettings* node_settings_;  // As being passed by CLI arguments and/or already initialized data
    mdbx::env* chaindata_env_;               // The actual opened environment

    std::map<const char*, std::unique_ptr<stagedsync::IStage>> stages_;
    std::map<const char*, std::unique_ptr<stagedsync::IStage>>::iterator current_stage_;
    std::vector<const char*> stages_forward_order_;
    std::vector<const char*> stages_unwind_order_;
    std::atomic<size_t> current_stages_count_{0};
    std::atomic<size_t> current_stage_number_{0};

    void work() final;   // The loop itself
    void load_stages();  // Fills the vector with stages

    //! \brief Runs a full sync cycle
    [[nodiscard]] StageResult run_cycle_forward(db::RWTxn& cycle_txn, Timer& log_timer);

    void throttle_next_cycle(const StopWatch::Duration& cycle_duration);  // Delays (if required) next cycle run
    std::string get_log_prefix() const;                                   // Returns the current log lines prefix on behalf of current stage
};
}  // namespace silkworm::stagedsync
