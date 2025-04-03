// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <concepts>
#include <optional>
#include <set>
#include <variant>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/datastore/kvdb/memory_mutation.hpp>
#include <silkworm/db/datastore/stage_scheduler.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/execution/api/endpoint/validation.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

#include "../timer_factory.hpp"
#include "canonical_chain.hpp"

namespace silkworm::stagedsync {

class Fork;
class ExtendingFork;

class MainChain {
  public:
    explicit MainChain(
        boost::asio::any_io_executor executor,
        NodeSettings& ns,
        db::DataModelFactory data_model_factory,
        std::optional<TimerFactory> log_timer_factory,
        StageContainerFactory stages_factory,
        datastore::kvdb::RWAccess dba);

    void open();  // needed to circumvent mdbx threading model limitations
    void close();
    void abort();

    // extension
    void insert_block(const Block&);

    // branching
    std::unique_ptr<ExtendingFork> fork(BlockId forking_point);  // fort at the current head
    void reintegrate_fork(ExtendingFork&);                       // reintegrate fork into the main chain
    std::optional<BlockId> find_forking_point(const BlockHeader& header, const Hash& header_hash) const;
    std::optional<BlockId> find_forking_point(const Hash& header_hash) const;
    bool is_finalized_canonical(BlockId block) const;

    // verification
    using VerificationResult = execution::api::VerificationResult;
    // verify chain up to head_block_hash
    VerificationResult verify_chain(Hash head_block_hash);
    // accept the current chain up to head_block_hash
    bool notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt);

    // state
    BlockId last_chosen_head() const;  // set by notify_fork_choice_update(), is always valid
    BlockId last_finalized_head() const;
    BlockId current_head() const;

    // header/body retrieval
    BlockNum get_block_progress() const;
    std::optional<BlockHeader> get_header(BlockNum, Hash) const;
    std::optional<Hash> get_finalized_canonical_hash(BlockNum) const;
    std::optional<TotalDifficulty> get_header_td(BlockNum, Hash) const;
    std::vector<BlockHeader> get_last_headers(uint64_t limit) const;
    bool extends_last_fork_choice(BlockNum, Hash) const;
    bool extends(BlockId block, BlockId supposed_parent) const;
    bool is_ancestor(BlockId supposed_parent, BlockId block) const;
    bool is_finalized_canonical(Hash) const;
    // Warning: this getters use kHeaderNumbers so will return only header processed by the pipeline
    std::optional<BlockHeader> get_header(Hash) const;
    std::optional<TotalDifficulty> get_header_td(Hash) const;
    std::optional<BlockBody> get_body(Hash) const;
    std::optional<BlockNum> get_block_num(Hash) const;
    BlockNum max_frozen_block_num() const;

    NodeSettings& node_settings();
    db::RWTxn& tx();  // only for testing purposes due to MDBX limitations
    const db::DataModelFactory& data_model_factory() const { return data_model_factory_; }
    const std::optional<TimerFactory>& log_timer_factory() const;
    const StageContainerFactory& stages_factory() const { return stages_factory_; }
    datastore::StageScheduler& stage_scheduler() const;

  protected:
    db::DataModel data_model() const { return data_model_factory_(tx_); }
    Hash insert_header(const BlockHeader&);
    void insert_body(const Block&, const Hash& block_hash);
    void forward(BlockNum head_block_num, const Hash& head_hash);
    void unwind(BlockNum unwind_point);

    bool is_canonical(BlockNum block_num, const Hash& block_hash) const;
    bool is_canonical_head_ancestor(const Hash& block_hash) const;

    std::set<Hash> collect_bad_headers(db::RWTxn& tx, execution::api::InvalidChain& invalid_chain);

    boost::asio::any_io_executor executor_;
    NodeSettings& node_settings_;
    db::DataModelFactory data_model_factory_;
    std::optional<TimerFactory> log_timer_factory_;
    StageContainerFactory stages_factory_;
    mutable datastore::kvdb::RWAccess db_access_;
    mutable datastore::kvdb::RWTxnManaged tx_;
    bool is_first_sync_{true};

    ExecutionPipeline pipeline_;
    CanonicalChain interim_canonical_chain_;
    VerificationResult interim_head_status_;
    BlockId last_fork_choice_;
    BlockId last_finalized_head_;
};

}  // namespace silkworm::stagedsync
