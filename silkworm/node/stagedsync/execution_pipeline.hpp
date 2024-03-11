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

#include <atomic>
#include <map>
#include <vector>

#include <silkworm/core/types/hash.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/node/db/stage.hpp>

namespace silkworm::stagedsync {

class ExecutionPipeline : public Stoppable {
  public:
    explicit ExecutionPipeline(NodeSettings*);
    ~ExecutionPipeline() override = default;

    Stage::Result forward(db::RWTxn&, BlockNum target_height);
    Stage::Result unwind(db::RWTxn&, BlockNum unwind_point);
    Stage::Result prune(db::RWTxn&);

    BlockNum head_header_number() const;
    Hash head_header_hash() const;
    std::optional<BlockNum> unwind_point();
    std::optional<Hash> bad_block();

    bool stop() override;

  private:
    silkworm::NodeSettings* node_settings_;
    std::unique_ptr<SyncContext> sync_context_;  // context shared across stages

    using StageContainer = std::map<const char*, std::unique_ptr<stagedsync::Stage>>;
    StageContainer stages_;
    StageContainer::iterator current_stage_;

    using StageNames = std::vector<const char*>;
    StageNames stages_forward_order_;
    StageNames stages_unwind_order_;
    std::atomic<size_t> current_stages_count_{0};
    std::atomic<size_t> current_stage_number_{0};

    BlockNum head_header_number_{0};
    Hash head_header_hash_;

    void load_stages();  // Fills the vector with stages

    std::string get_log_prefix() const;  // Returns the current log lines prefix on behalf of current stage
    class LogTimer;                      // Timer for async log scheduling
    std::unique_ptr<LogTimer> make_log_timer();
};

}  // namespace silkworm::stagedsync
