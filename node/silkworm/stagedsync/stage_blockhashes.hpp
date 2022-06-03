/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_STAGEDSYNC_STAGE_BLOCKHASHES_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_BLOCKHASHES_HPP_

#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

class BlockHashes final : public IStage {
  public:
    explicit BlockHashes(NodeSettings* node_settings) : IStage(db::stages::kBlockHashesKey, node_settings){};
    ~BlockHashes() override = default;

    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn, BlockNum to) final;
    StageResult prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    std::unique_ptr<etl::Collector> collector_{nullptr};

    /* Stats */
    uint16_t current_phase_{0};
    BlockNum reached_block_num_{0};
};

} // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_STAGE_BLOCKHASHES_HPP_
