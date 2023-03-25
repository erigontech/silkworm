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
#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class ExecutionPipeline : public Stoppable {
  public:
    explicit ExecutionPipeline(NodeSettings*);
    ~ExecutionPipeline() = default;

    Stage::Result forward(db::RWTxn&, BlockNum target_height);
    Stage::Result unwind(db::RWTxn&, BlockNum unwind_point);
    Stage::Result prune(db::RWTxn&);

    BlockNum head_header_number();
    Hash head_header_hash();
    std::optional<BlockNum> unwind_point();
    std::optional<Hash> bad_block();

    bool stop() override;

  private:
    silkworm::NodeSettings* node_settings_;
    std::unique_ptr<SyncContext> sync_context_;  // context shared across stages

    using Stage_Container = std::map<const char*, std::unique_ptr<stagedsync::Stage>>;
    Stage_Container stages_;

    Stage_Container::iterator current_stage_;
    std::vector<const char*> stages_forward_order_;
    std::vector<const char*> stages_unwind_order_;
    std::atomic<size_t> current_stages_count_{0};
    std::atomic<size_t> current_stage_number_{0};

    BlockNum head_header_number_{0};
    Hash head_header_hash_;

    void load_stages();  // Fills the vector with stages

    std::string get_log_prefix() const;  // Returns the current log lines prefix on behalf of current stage
    class LogTimer;                      // Timer for async log scheduling
};
}  // namespace silkworm::stagedsync
