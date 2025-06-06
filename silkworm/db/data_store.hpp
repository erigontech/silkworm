// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include "blocks/schema_config.hpp"
#include "datastore/data_store.hpp"
#include "state/schema_config.hpp"

namespace silkworm::db {

struct DataStoreRef {
    datastore::kvdb::DatabaseRef chaindata;
    state::StateDatabaseRef state_db() const { return {chaindata}; }
    snapshots::SnapshotRepository& blocks_repository;
    snapshots::SnapshotRepository& state_repository_latest;
    snapshots::SnapshotRepository& state_repository_historical;
    const snapshots::QueryCaches& query_caches;
};

class DataStore {
    DataStore(
        datastore::kvdb::Database chaindata_database,
        snapshots::SnapshotRepository blocks_repository,
        snapshots::SnapshotRepository state_repository_latest,
        snapshots::SnapshotRepository state_repository_historical)
        : store_{
              make_schema(),
              make_databases_map(std::move(chaindata_database)),
              make_repositories_map(
                  std::move(blocks_repository),
                  std::move(state_repository_latest),
                  std::move(state_repository_historical)),
              blocks_repository.path(),
          } {}

  public:
    explicit DataStore(datastore::DataStore store) : store_{std::move(store)} {}

    DataStore(
        mdbx::env_managed chaindata_env,
        const std::filesystem::path& repository_path)
        : DataStore{
              make_chaindata_database(std::move(chaindata_env)),
              blocks::make_blocks_repository(repository_path),
              state::make_state_repository_latest(repository_path),
              state::make_state_repository_historical(repository_path),
          } {}

    DataStore(
        const datastore::kvdb::EnvConfig& chaindata_env_config,
        const std::filesystem::path& repository_path)
        : DataStore{
              datastore::kvdb::open_env(chaindata_env_config),
              repository_path,
          } {}

    DataStoreRef ref() const {
        return {
            chaindata().ref(),
            blocks_repository(),
            state_repository_latest(),
            state_repository_historical(),
            store_.query_caches(),
        };
    }

    datastore::kvdb::Database& chaindata() const { return store_.default_database(); }

    snapshots::SnapshotRepository& blocks_repository() const {
        return store_.repository(blocks::kBlocksRepositoryName);
    }
    snapshots::SnapshotRepository& state_repository_latest() const {
        return store_.repository(state::kStateRepositoryNameLatest);
    }
    snapshots::SnapshotRepository& state_repository_historical() const {
        return store_.repository(state::kStateRepositoryNameHistorical);
    }
    const snapshots::QueryCaches& query_caches() const { return store_.query_caches(); }

    static datastore::kvdb::Schema::DatabaseDef make_chaindata_database_schema();
    static datastore::kvdb::Database make_chaindata_database(mdbx::env_managed chaindata_env);
    static datastore::kvdb::DatabaseUnmanaged make_chaindata_database(datastore::kvdb::EnvUnmanaged chaindata_env);

  private:
    static datastore::Schema make_schema();

    static datastore::EntityMap<std::unique_ptr<datastore::kvdb::Database>> make_databases_map(
        datastore::kvdb::Database chaindata_database);
    static datastore::EntityMap<std::unique_ptr<snapshots::SnapshotRepository>> make_repositories_map(
        snapshots::SnapshotRepository blocks_repository,
        snapshots::SnapshotRepository state_repository_latest,
        snapshots::SnapshotRepository state_repository_historical);

    datastore::DataStore store_;
};

}  // namespace silkworm::db
