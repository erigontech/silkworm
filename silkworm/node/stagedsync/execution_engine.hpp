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

#include "forks/fork.hpp"

#include <atomic>
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

class ExecutionEngine : public Stoppable {
  public:
    explicit ExecutionEngine(NodeSettings&, db::RWAccess);

    using VerificationResult = Fork::VerificationResult;

    // actions
    void insert_blocks(std::vector<std::shared_ptr<Block>>& blocks);
    void insert_block(const Block& block);

    auto verify_chain(Hash head_block_hash) -> VerificationResult;

    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    auto last_fork_choice() -> BlockId;

  protected:
    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    db::RWTxn tx_;
    bool is_first_sync_{true};

    std::vector<Fork> forks_;
    BlockId last_fork_choice_;
};

}  // namespace silkworm::stagedsync
