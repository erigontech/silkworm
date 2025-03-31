// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <concepts>
#include <memory>
#include <optional>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/execution/api/execution_engine.hpp>
#include <silkworm/infra/concurrency/context_pool.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "forks/extending_fork.hpp"
#include "forks/main_chain.hpp"
#include "timer_factory.hpp"

namespace silkworm::stagedsync {

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
class ExecutionEngine : public execution::api::ExecutionEngine, public Stoppable {
  public:
    ExecutionEngine(
        std::optional<boost::asio::any_io_executor> executor,
        NodeSettings& ns,
        db::DataModelFactory data_model_factory,
        std::optional<TimerFactory> log_timer_factory,
        StageContainerFactory stages_factory,
        datastore::kvdb::RWAccess dba);
    ~ExecutionEngine() override = default;

    // needed to circumvent mdbx threading model limitations
    void open() override;
    void close() override;

    // actions
    void insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks) override;
    bool insert_block(const std::shared_ptr<Block>& block);

    execution::api::VerificationResult verify_chain_no_fork_tracking(Hash head_block_hash);
    Task<execution::api::VerificationResult> verify_chain(Hash head_block_hash) override;

    bool notify_fork_choice_update(
        Hash head_block_hash,
        std::optional<Hash> finalized_block_hash,
        std::optional<Hash> safe_block_hash) override;

    // state
    BlockNum block_progress() const override;
    BlockId last_fork_choice() const override;
    BlockId last_finalized_block() const override;
    BlockId last_safe_block() const override;
    BlockNum max_frozen_block_num() const override;

    // header/body retrieval
    std::optional<BlockHeader> get_header(Hash) const override;
    std::optional<BlockHeader> get_header(BlockNum, Hash) const;
    std::optional<BlockHeader> get_canonical_header(BlockNum) const override;
    std::optional<Hash> get_canonical_hash(BlockNum) const override;
    std::optional<BlockBody> get_body(Hash) const override;
    std::optional<BlockBody> get_canonical_body(BlockNum) const override;
    bool is_canonical(Hash) const override;
    std::optional<BlockNum> get_block_num(Hash) const override;
    std::vector<BlockHeader> get_last_headers(uint64_t limit) const override;
    std::optional<TotalDifficulty> get_header_td(Hash, std::optional<BlockNum>) const override;

    datastore::StageScheduler& stage_scheduler() const;

  protected:
    struct ForkingPath {
        BlockId forking_point;
        std::list<std::shared_ptr<Block>> blocks;  // blocks in reverse order
    };

    std::optional<ForkingPath> find_forking_point(const BlockHeader& header) const;
    void discard_all_forks();

    std::unique_ptr<concurrency::ContextPool<>> context_pool_;
    boost::asio::any_io_executor executor_;
    NodeSettings& node_settings_;

    MainChain main_chain_;
    ForkContainer forks_;

    static constexpr size_t kDefaultCacheSize = 1000;
    mutable LruCache<Hash, std::shared_ptr<Block>> block_cache_;

    BlockNum block_progress_{0};
    bool fork_tracking_active_{false};
    BlockId last_fork_choice_;
    BlockId last_finalized_block_;
    BlockId last_safe_block_;
};

}  // namespace silkworm::stagedsync
