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

#include "forks/extending_fork.hpp"
#include "forks/main_chain.hpp"

#define ERIGON_API

namespace silkworm::stagedsync {

namespace asio = boost::asio;

/**
 * ExecutionEngine is the main component of the staged sync.
 * It is responsible for:
 * - inserting blocks keeping track of forks
 * - verifying forks managing some parallel executions of the pipeline
 * - exposing a consistent view of the chain
 *
 * Its interface is sync to maintain a simple and consistent state but on forks:
 * - block insertion & chain verification immediately return
 * - notify_fork_choice_update need to block to set a consistent view of the chain
 * On main-chain operations are blocking because when there are no forks we do not need async execution
 */
class ExecutionEngine : public Stoppable {
  public:
    explicit ExecutionEngine(asio::io_context&, NodeSettings&, db::RWAccess);

    void open();  // needed to circumvent mdbx threading model limitations

    // actions
    void insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks);
    bool insert_block(std::shared_ptr<Block> block);

    auto verify_chain(Hash head_block_hash) -> concurrency::AwaitableFuture<VerificationResult>;

    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    auto block_progress() const -> BlockNum;
    auto last_finalized_block() const -> BlockId;
    auto last_fork_choice() const -> BlockId;

    // header/body retrieval
    auto get_header(Hash) const -> std::optional<BlockHeader>;
    auto get_header(BlockNum) const -> std::optional<BlockHeader>;
    auto get_body(Hash) const -> std::optional<BlockBody>;
    auto get_body(BlockNum) const -> std::optional<BlockBody>;
    bool is_canonical_hash(Hash) const;
    auto get_block_number(Hash) const -> std::optional<BlockNum>;
    auto get_last_headers(BlockNum limit) const -> std::vector<BlockHeader>;

    /*
    auto get_canonical_head() const -> BlockId;
    auto get_canonical_hash(BlockNum) const -> std::optional<Hash>;
    auto get_header_td(BlockNum, Hash) const -> std::optional<TotalDifficulty>;
    auto get_body(Hash) const -> std::optional<BlockBody>;
    auto extends_last_fork_choice(BlockNum, Hash) const -> bool;
    auto extends(BlockId block, BlockId supposed_parent) const -> bool;
    */
  protected:
    struct ForkingPath {
        BlockId forking_point;
        std::list<std::shared_ptr<Block>> blocks;  // blocks in reverse order
    };

    auto find_forking_point(const BlockHeader& header) const -> std::optional<ForkingPath>;
    void discard_all_forks();

    asio::io_context& io_context_;
    NodeSettings& node_settings_;
    db::RWAccess db_access_;

    MainChain main_chain_;
    std::vector<ExtendingFork> forks_;

    static constexpr size_t kDefaultCacheSize = 1000;
    mutable lru_cache<Hash, std::shared_ptr<Block>> block_cache_;

    BlockNum block_progress_{0};
    bool fork_tracking_active_{false};
    BlockId last_finalized_block_;
    BlockId last_fork_choice_;
};

}  // namespace silkworm::stagedsync
