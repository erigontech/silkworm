// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/circular_buffer.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class Execution final : public Stage {
  public:
    Execution(
        SyncContext* sync_context,
        db::DataModelFactory data_model_factory,
        const ChainConfig& chain_config,
        size_t batch_size,
        db::PruneMode prune_mode)
        : Stage(sync_context, db::stages::kExecutionKey),
          data_model_factory_(std::move(data_model_factory)),
          chain_config_(chain_config),
          batch_size_(batch_size),
          prune_mode_(prune_mode),
          rule_set_{protocol::rule_set_factory(chain_config)} {}

    ~Execution() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    static constexpr size_t kMaxPrefetchedBlocks{10240};

    db::DataModelFactory data_model_factory_;
    const ChainConfig& chain_config_;
    size_t batch_size_;
    db::PruneMode prune_mode_;
    protocol::RuleSetPtr rule_set_;
    BlockNum block_num_{0};
    boost::circular_buffer<Block> prefetched_blocks_{/*buffer_capacity=*/kMaxPrefetchedBlocks};

    //! \brief Prefetches blocks for processing
    //! \param [in] from: the first block to prefetch (inclusive)
    //! \param [in] to: the last block to prefetch (inclusive)
    //! \remarks The amount of blocks to be fetched is determined by the upper block number (to)
    //! or kMaxPrefetchedBlocks collected, whichever comes first
    void prefetch_blocks(db::RWTxn& txn, BlockNum from, BlockNum to);

    //! \brief Executes a batch of blocks
    //! \remarks A batch completes when either max block is reached or buffer dimensions overflow
    Stage::Result execute_batch(db::RWTxn& txn, BlockNum max_block_num, AnalysisCache& analysis_cache,
                                BlockNum prune_history_threshold, BlockNum prune_receipts_threshold,
                                BlockNum prune_call_traces_threshold);

    //! \brief For given changeset cursor/bucket it reverts the changes on states buckets
    static void unwind_state_from_changeset(datastore::kvdb::ROCursor& source_changeset, datastore::kvdb::RWCursorDupSort& plain_state_table,
                                            datastore::kvdb::RWCursor& plain_code_table, BlockNum unwind_to);

    //! \brief Revert State for given address/storage location
    static void revert_state(ByteView key, ByteView value, datastore::kvdb::RWCursorDupSort& plain_state_table,
                             datastore::kvdb::RWCursor& plain_code_table);

    // Stats
    std::mutex progress_mtx_;  // Synchronizes access to progress stats
    std::chrono::time_point<std::chrono::steady_clock> lap_time_{std::chrono::steady_clock::now()};
    size_t processed_blocks_{0};
    size_t processed_transactions_{0};
    size_t processed_gas_{0};
};

}  // namespace silkworm::stagedsync
