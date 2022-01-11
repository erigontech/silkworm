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

#ifndef SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_
#define SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_

// See https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md

#include <filesystem>
#include <vector>

#include <silkworm/consensus/engine.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/analysis_cache.hpp>
#include <silkworm/execution/state_pool.hpp>
#include <silkworm/stagedsync/common.hpp>
#include <silkworm/stagedsync/recovery/recovery_farm.hpp>

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

class Senders final : public IStage {
  public:
    explicit Senders(NodeSettings* node_settings) : IStage(db::stages::kSendersKey, node_settings){};
    ~Senders() override = default;

    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn, BlockNum to) final;
    StageResult prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    std::unique_ptr<recovery::RecoveryFarm> farm_{nullptr};
};

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
    StageResult execute_batch(db::RWTxn& txn, BlockNum max_block_num, BlockNum prune_from,
                              AnalysisCache& analysis_cache, ExecutionStatePool& state_pool);

    // Stats
    std::mutex progress_mtx_;  // Synchronizes access to progress stats
    std::chrono::time_point<std::chrono::steady_clock> lap_time_{std::chrono::steady_clock::now()};
    size_t processed_blocks_{0};
    size_t processed_transactions_{0};
    size_t processed_gas_{0};
};

inline constexpr size_t kDefaultBatchSize = 512_Mebi;          // TODO(Andrea) Replace with value from CLI

typedef StageResult (*StageFunc)(db::RWTxn&, const std::filesystem::path& etl_path, uint64_t prune_from);
typedef StageResult (*UnwindFunc)(db::RWTxn&, const std::filesystem::path& etl_path, uint64_t unwind_to);
typedef StageResult (*PruneFunc)(db::RWTxn&, const std::filesystem::path& etl_path, uint64_t prune_from);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    PruneFunc prune_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_bodies(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_execution(db::RWTxn& txn, const std::filesystem::path& etl_path, size_t batch_size,
                            uint64_t prune_from);
inline StageResult stage_execution(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0) {
    return stage_execution(txn, etl_path, kDefaultBatchSize, prune_from);
}

/* HashState Promotion Functions*/

/*
    * Operation is used to distinguish what bucket we want to generated
    * HashAccount is for generating HashedAccountBucket
    * HashStorage is for generating HashedStorageBucket
    * Code generates hashed key => code_hash mapping

*/
enum class HashstateOperation {
    HashAccount,
    HashStorage,
    Code,
};

void hashstate_promote(mdbx::txn&, HashstateOperation);
void hashstate_promote_clean_code(mdbx::txn& txn, const std::filesystem::path& etl_path);
void hashstate_promote_clean_state(mdbx::txn& txn, const std::filesystem::path& etl_path);

/* **************************** */
StageResult stage_hashstate(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_interhashes(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);

// Unwind functions
StageResult no_unwind(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_execution(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_hashstate(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_interhashes(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);

// Prune functions
StageResult no_prune(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_execution(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);

std::vector<Stage> get_archive_node_stages();
std::vector<Stage> get_pruned_node_stages();
std::vector<Stage> get_miner_mode_stages();

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_
