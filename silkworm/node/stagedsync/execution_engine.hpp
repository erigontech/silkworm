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
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/infra/common/asio_timer.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

#include "forks/main_chain.hpp"
#include "forks/suspendable_fork.hpp"

namespace silkworm::stagedsync {

namespace asio = boost::asio;

class ExecutionEngine : public Stoppable {
  public:
    explicit ExecutionEngine(NodeSettings&, db::RWAccess);

    // actions
    void insert_blocks(std::vector<std::shared_ptr<Block>>& blocks);
    void insert_block(std::shared_ptr<Block> block);

    auto verify_chain(Hash head_block_hash) -> asio::awaitable<VerificationResult>;

    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    auto last_fork_choice() -> std::optional<BlockId>;

  protected:
    struct ForkingPath {
        BlockId forking_point;
        std::list<std::shared_ptr<Block>> blocks;  // blocks in reverse order
    };

    auto find_forking_point(const BlockHeader& header) const -> std::optional<ForkingPath>;
    void consolidate_forks();

    NodeSettings& node_settings_;
    db::RWAccess db_access_;
    db::RWTxn tx_;

    MainChain main_chain_;
    std::vector<ExtendingFork> forks_;

    static constexpr size_t kDefaultCacheSize = 1000;
    mutable lru_cache<Hash, std::shared_ptr<Block>> block_cache_;

    bool fork_tracking_active_{false};
    std::optional<BlockId> last_fork_choice_;
    std::optional<Hash> last_finalized_block_;
};

}  // namespace silkworm::stagedsync
