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

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/io_context.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "forks/extending_fork.hpp"
#include "forks/main_chain.hpp"

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
    ExecutionEngine(asio::io_context&, NodeSettings&, db::RWAccess);
    ~ExecutionEngine() override = default;

    void open();  // needed to circumvent mdbx threading model limitations
    void close();

    // actions
    virtual void insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks);
    bool insert_block(const std::shared_ptr<Block>& block);

    VerificationResult verify_chain_no_fork_tracking(Hash head_block_hash);
    virtual Task<VerificationResult> verify_chain(Hash head_block_hash);

    virtual bool notify_fork_choice_update(Hash head_block_hash,
                                           std::optional<Hash> finalized_block_hash,
                                           std::optional<Hash> safe_block_hash);

    // state
    virtual BlockNum block_progress() const;
    virtual BlockId last_fork_choice() const;
    virtual BlockId last_finalized_block() const;
    virtual BlockId last_safe_block() const;

    // header/body retrieval
    std::optional<BlockHeader> get_header(Hash) const;
    std::optional<BlockHeader> get_header(BlockNum, Hash) const;
    std::optional<BlockHeader> get_canonical_header(BlockNum) const;
    std::optional<Hash> get_canonical_hash(BlockNum) const;
    std::optional<BlockBody> get_body(Hash) const;
    std::optional<BlockBody> get_canonical_body(BlockNum) const;
    bool is_canonical(Hash) const;
    virtual std::optional<BlockNum> get_block_number(Hash) const;
    virtual std::vector<BlockHeader> get_last_headers(uint64_t limit) const;
    std::optional<TotalDifficulty> get_header_td(Hash, std::optional<BlockNum> = std::nullopt) const;

  protected:
    struct ForkingPath {
        BlockId forking_point;
        std::list<std::shared_ptr<Block>> blocks;  // blocks in reverse order
    };

    std::optional<ForkingPath> find_forking_point(const BlockHeader& header) const;
    void discard_all_forks();

    asio::io_context& io_context_;
    NodeSettings& node_settings_;

    MainChain main_chain_;
    ForkContainer forks_;

    static constexpr size_t kDefaultCacheSize = 1000;
    mutable lru_cache<Hash, std::shared_ptr<Block>> block_cache_;

    BlockNum block_progress_{0};
    bool fork_tracking_active_{false};
    BlockId last_fork_choice_;
    BlockId last_finalized_block_;
    BlockId last_safe_block_;
};

}  // namespace silkworm::stagedsync
