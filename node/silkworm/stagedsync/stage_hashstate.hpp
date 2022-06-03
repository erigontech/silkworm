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

#ifndef SILKWORM_STAGEDSYNC_STAGE_HASHSTATE_HPP_
#define SILKWORM_STAGEDSYNC_STAGE_HASHSTATE_HPP_

#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

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
    StageResult write_changes_from_changed_addresses(db::RWTxn& txn, const ChangedAddresses& changed_addresses);

    //! \brief Writes to db the changes collected from storage changeset scan either in forward or unwind mode
    StageResult write_changes_from_changed_storage(db::RWTxn& txn, db::StorageChanges& storage_changes,
                                                   const absl::btree_map<evmc::address, evmc::bytes32>& hashed_addresses);

    //! \brief Resets all fields related to log progress tracking
    void reset_log_progress();

    // Logger info
    std::mutex log_mtx_{};                       // Guards async logging
    std::atomic_bool incremental_{false};        // Whether operation is incremental
    std::atomic_bool loading_{false};            // Whether we're in ETL loading phase
    std::string current_source_;                 // Current source of data
    std::string current_target_;                 // Current target of transformed data
    std::string current_key_;                    // Actual processing key
    std::unique_ptr<etl::Collector> collector_;  // Collector (used only in !incremental_)
};

} // namespace silkworm::stagedsync
#endif  // SILKWORM_STAGEDSYNC_STAGE_HASHSTATE_HPP_
