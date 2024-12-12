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

#include <silkworm/db/datastore/etl/collector_settings.hpp>
#include <silkworm/db/stage.hpp>

namespace silkworm::stagedsync {

class HashState final : public Stage {
  public:
    HashState(
        SyncContext* sync_context,
        datastore::etl::CollectorSettings etl_settings)
        : Stage(sync_context, db::stages::kHashStateKey),
          etl_settings_(std::move(etl_settings)) {}
    HashState(const HashState&) = delete;  // not copyable
    HashState(HashState&&) = delete;       // nor movable
    ~HashState() override = default;

    Stage::Result forward(db::RWTxn& txn) final;
    Stage::Result unwind(db::RWTxn& txn) final;
    Stage::Result prune(db::RWTxn& txn) final;
    std::vector<std::string> get_log_progress() final;

  private:
    //! \brief Store already processed addresses to avoid rehashing and multiple lookups
    //! \struct Address -> Address Hash -> Value
    using ChangedAddresses = absl::btree_map<evmc::address, std::pair<evmc::bytes32, Bytes>>;

    //! \brief Transforms PlainState into HashedAccounts and HashedStorage respectively in one single read pass over
    //! PlainState \remarks To be used only if this is very first time HashState stage runs forward (i.e. forwarding
    //! from 0)
    Stage::Result hash_from_plainstate(db::RWTxn& txn);

    //! \brief Transforms PlainCodeHash into HashedCodeHash in one single read pass over PlainCodeHash
    //! \remarks To be used only if this is very first time HashState stage runs forward (i.e. forwarding from 0)
    Stage::Result hash_from_plaincode(db::RWTxn& txn);

    //! \brief Detects account changes from AccountChangeSet and hashes the changed keys
    //! \remarks Though it could be used for initial sync only is way slower and builds an index of changed accounts.
    Stage::Result hash_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects storage changes from StorageChangeSet and hashes the changed keys
    //! \remarks Though it could be used for initial sync only is way slower and builds an index of changed storage
    //! locations.
    Stage::Result hash_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects account changes from AccountChangeSet and reverts hashed states
    Stage::Result unwind_from_account_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Detects storage changes from StorageChangeSet and reverts hashed states
    Stage::Result unwind_from_storage_changeset(db::RWTxn& txn, BlockNum previous_progress, BlockNum to);

    //! \brief Writes to db the changes collected from account changeset scan either in forward or unwind mode
    void write_changes_from_changed_addresses(db::RWTxn& txn, const ChangedAddresses& changed_addresses);

    //! \brief Writes to db the changes collected from storage changeset scan either in forward or unwind mode
    void write_changes_from_changed_storage(db::RWTxn& txn, silkworm::db::StorageChanges& storage_changes,
                                            const absl::btree_map<evmc::address, evmc::bytes32>& hashed_addresses);

    //! \brief Resets all fields related to log progress tracking
    void reset_log_progress();

    // Guards async logging
    std::mutex log_mtx_{};

    // Whether operation is incremental
    std::atomic_bool incremental_{false};
    // Whether we're in ETL loading phase
    std::atomic_bool loading_{false};

    // Current source of data
    std::string current_source_;
    // Current target of transformed data
    std::string current_target_;
    // Actual processing key
    std::string current_key_;

    // Collector (used only in !incremental_)
    datastore::etl::CollectorSettings etl_settings_;
    std::unique_ptr<datastore::kvdb::Collector> collector_;
};

}  // namespace silkworm::stagedsync
