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

#pragma once
#ifndef SILKWORM_STAGEDSYNC_SYNCLOOP_HPP_
#define SILKWORM_STAGEDSYNC_SYNCLOOP_HPP_

#include <silkworm/common/settings.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/concurrency/worker.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedysnc {
class SyncLoop final : public Worker {
  public:
    explicit SyncLoop(silkworm::NodeSettings* node_settings, mdbx::env* chaindata_env)
        : Worker("SyncLoop"), node_settings_{node_settings}, chaindata_env_{chaindata_env} {
        load_stages();
    };
    ~SyncLoop() override = default;

  private:
    silkworm::NodeSettings* node_settings_;  // As being passed by CLI arguments and/or already initialized data
    mdbx::env* chaindata_env_;               // The actual opened environment
    std::vector<std::unique_ptr<stagedsync::IStage>> stages_{};  // Collection of stages
    size_t current_stage_{0};                                    // Index of current stage
    void work() override;                                        // The loop itself
    void load_stages();                                          // Fills the vector of stages

    void throttle_next_cycle(const StopWatch::Duration& cycle_duration);  // Delays (if required) next cycle run
};
}  // namespace silkworm::stagedysnc
#endif  // SILKWORM_STAGEDSYNC_SYNCLOOP_HPP_
