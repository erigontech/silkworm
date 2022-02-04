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
    bool stop() final;

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

class HashState final : public IStage {
  public:
    explicit HashState(NodeSettings* node_settings)
        : IStage(db::stages::kHashStateKey, node_settings),
          collector_(std::make_unique<etl::Collector>(node_settings)){};
    ~HashState() override = default;
    StageResult forward(db::RWTxn& txn) final;
    StageResult unwind(db::RWTxn& txn, BlockNum to) final;
    StageResult prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    //! \brief Store already processed addresses to avoid rehashing and multiple lookups
    //! \struct Address -> Address Hash -> Value
    using ChangedAddresses = absl::btree_map<evmc::address, std::pair<evmc::bytes32, Bytes>>;

    //! \brief Transforms PlainState into HashedAccounts and HashedStorage respectively in one single read pass over
    //! PlainState \remarks To be used only if this is very first time HashState stage runs forward (i.e. forwarding
    //! from 0)
    StageResult hash_from_plainstate(db::RWTxn& txn);

    //! \brief Transforms PlainCodeHash into HashedCodeHash in one single read pass over PlainCodeHash
    //! \remarks To be used only if this is very first time HashState stage runs forward (i.e. forwarding from 0)
    StageResult hash_from_plaincode(db::RWTxn& txn);

    //! \brief Detects account changes from AccountChangeSet and hashes the changed keys
    //! \remarks Though it could be used for initial sync only is way slower and builds an index of changed accounts.
    StageResult hash_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects storage changes from StorageChangeSet and hashes the changed keys
    //! \remarks Though it could be used for initial sync only is way slower and builds an index of changed storage
    //! locations.
    StageResult hash_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects account changes from AccountChangeSet and reverts hashed states
    StageResult unwind_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects storage changes from StorageChangeSet and reverts hashed states
    StageResult unwind_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Writes to db the changes collected from account changeset scan either in forward or unwind mode
    StageResult write_changes_from_changed_addresses(db::RWTxn& txn, ChangedAddresses& changed_addresses);

    //! \brief Writes to db the changes collected from storage changeset scan either in forward or unwind mode
    StageResult write_changes_from_changed_storage(db::RWTxn& txn, db::StorageChanges& storage_changes,
                                                   absl::btree_map<evmc::address, evmc::bytes32>& hashed_addresses);

    //! \brief Resets all fields related to log progress tracking
    void reset_log_progress();

    // Logger info
    std::atomic_bool incremental_{false};        // Whether operation is incremental
    std::atomic_bool loading_{false};            // Whether we're in ETL loading phase
    std::string current_source_;                 // Current source of data
    std::string current_target_;                 // Current target of transformed data
    std::string current_key_;                    // Actual processing key
    std::unique_ptr<etl::Collector> collector_;  // Collector (used only in !incremental_)
};

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

/* **************************** */
StageResult stage_interhashes(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);

// Unwind functions
StageResult no_unwind(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_interhashes(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);

// Prune functions
StageResult no_prune(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);

std::vector<Stage> get_archive_node_stages();
std::vector<Stage> get_pruned_node_stages();
std::vector<Stage> get_miner_mode_stages();

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_
