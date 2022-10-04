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
#include <silkworm/downloader/block_exchange.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class SyncLoop final : public Worker {
  public:
    explicit SyncLoop(silkworm::NodeSettings*, mdbx::env*, BlockExchange&);
    ~SyncLoop() override = default;

    void stop(bool wait = false) final;

  private:
    silkworm::NodeSettings* node_settings_;      // As being passed by CLI arguments and/or already initialized data
    mdbx::env* chaindata_env_;                   // The actual opened environment
    BlockExchange& block_exchange_;              // The block downloader
    std::unique_ptr<SyncContext> sync_context_;  // Context shared across stages
    std::map<const char*, std::unique_ptr<stagedsync::Stage>> stages_;
    std::map<const char*, std::unique_ptr<stagedsync::Stage>>::iterator current_stage_;
    std::vector<const char*> stages_forward_order_;
    std::vector<const char*> stages_unwind_order_;
    std::atomic<size_t> current_stages_count_{0};
    std::atomic<size_t> current_stage_number_{0};

    void work() final;   // The loop itself
    void load_stages();  // Fills the vector with stages

    //! \brief Runs a full forward cycle
    [[nodiscard]] Stage::Result run_cycle_forward(db::RWTxn& cycle_txn, Timer& log_timer);

    //! \brief Runs a full unwind cycle
    [[nodiscard]] Stage::Result run_cycle_unwind(db::RWTxn& cycle_txn, Timer& log_timer);

    //! \brief Runs a full prune cycle
    [[nodiscard]] Stage::Result run_cycle_prune(db::RWTxn& cycle_txn, Timer& log_timer);

    void throttle_next_cycle(const StopWatch::Duration& cycle_duration);  // Delays (if required) next cycle run
    std::string get_log_prefix() const;                                   // Returns the current log lines prefix on behalf of current stage
};
}  // namespace silkworm::stagedsync
