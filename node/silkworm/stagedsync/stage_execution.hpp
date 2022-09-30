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

#include <boost/circular_buffer.hpp>

#include <silkworm/consensus/engine.hpp>
#include <silkworm/execution/analysis_cache.hpp>
#include <silkworm/execution/evm.hpp>
#include <silkworm/stagedsync/stage.hpp>

namespace silkworm::stagedsync {

class Execution final : public Stage {
  public:
    explicit Execution(NodeSettings* node_settings, SyncContext* sync_context)
        : Stage(sync_context, db::stages::kExecutionKey, node_settings),
          consensus_engine_{consensus::engine_factory(node_settings->chain_config.value())} {}

    ~Execution() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    static constexpr size_t kMaxPrefetchedBlocks{10240};

    std::unique_ptr<consensus::IEngine> consensus_engine_;
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
    Stage::Result execute_batch(db::RWTxn& txn, BlockNum max_block_num, BaselineAnalysisCache& analysis_cache,
                                ObjectPool<EvmoneExecutionState>& state_pool, BlockNum prune_history_threshold,
                                BlockNum prune_receipts_threshold);

    //! \brief For given changeset cursor/bucket it reverts the changes on states buckets
    static void unwind_state_from_changeset(mdbx::cursor& source_changeset, mdbx::cursor& plain_state_table,
                                            mdbx::cursor& plain_code_table, BlockNum unwind_to);

    //! \brief Revert State for given address/storage location
    static void revert_state(ByteView key, ByteView value, mdbx::cursor& plain_state_table,
                             mdbx::cursor& plain_code_table);

    // Stats
    std::mutex progress_mtx_;  // Synchronizes access to progress stats
    std::chrono::time_point<std::chrono::steady_clock> lap_time_{std::chrono::steady_clock::now()};
    size_t processed_blocks_{0};
    size_t processed_transactions_{0};
    size_t processed_gas_{0};
};

}  // namespace silkworm::stagedsync
