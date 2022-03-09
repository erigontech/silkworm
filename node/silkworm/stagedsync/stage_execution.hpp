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

#ifndef SILKWORM_STAGEDSYNC_STAGE_EXECUTION_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_EXECUTION_HPP_

#include <queue>

#include <silkworm/consensus/engine.hpp>
#include <silkworm/execution/analysis_cache.hpp>
#include <silkworm/execution/evm.hpp>
#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

class Execution final : public IStage {
  public:
    explicit Execution(NodeSettings* node_settings)
        : IStage(db::stages::kExecutionKey, node_settings),
          consensus_engine_{consensus::engine_factory(node_settings->chain_config.value())} {};
    ~Execution() override = default;

    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn, BlockNum to) final;
    StageResult prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    std::unique_ptr<consensus::IEngine> consensus_engine_;
    BlockNum block_num_{0};

    //! \brief Prefetches blocks for processing
    //! \remarks The amount of blocks to be fetched is determined by the upper block number (to) or max_blocks collected
    //! whichever comes first
    static std::queue<Block> prefetch_blocks(db::RWTxn& txn, BlockNum from, BlockNum to, size_t max_blocks);

    //! \brief Executes a batch of blocks
    //! \remarks A batch completes when either max block is reached or buffer dimensions overflow
    StageResult execute_batch(db::RWTxn& txn, BlockNum max_block_num, AnalysisCache& analysis_cache,
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

#endif  // SILKWORM_STAGEDSYNC_STAGE_EXECUTION_HPP_
