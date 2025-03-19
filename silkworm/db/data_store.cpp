/*
   Copyright 2024 The Silkworm Authors

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

#include "data_store.hpp"

namespace silkworm::db {

datastore::Schema DataStore::make_schema() {
    datastore::kvdb::Schema kvdb;
    kvdb.default_database() = make_chaindata_database_schema();

    snapshots::Schema snapshots;
    snapshots.repository(blocks::kBlocksRepositoryName) = blocks::make_blocks_repository_schema();
    snapshots.repository(state::kStateRepositoryNameLatest) = state::make_state_repository_schema_latest();
    snapshots.repository(state::kStateRepositoryNameHistorical) = state::make_state_repository_schema_historical();

    return {
        std::move(kvdb),
        std::move(snapshots),
    };
}

datastore::kvdb::Schema::DatabaseDef DataStore::make_chaindata_database_schema() {
    return state::make_state_database_schema();
}

datastore::kvdb::Database DataStore::make_chaindata_database(mdbx::env_managed chaindata_env) {
    return {
        std::move(chaindata_env),
        make_chaindata_database_schema(),
    };
}

datastore::kvdb::DatabaseUnmanaged DataStore::make_chaindata_database(datastore::kvdb::EnvUnmanaged chaindata_env) {
    return {
        std::move(chaindata_env),
        make_chaindata_database_schema(),
    };
}

datastore::EntityMap<std::unique_ptr<datastore::kvdb::Database>> DataStore::make_databases_map(
    datastore::kvdb::Database chaindata_database) {
    datastore::EntityMap<std::unique_ptr<datastore::kvdb::Database>> databases;
    databases.emplace(datastore::kvdb::Schema::kDefaultEntityName, std::make_unique<datastore::kvdb::Database>(std::move(chaindata_database)));
    return databases;
}

datastore::EntityMap<std::unique_ptr<snapshots::SnapshotRepository>> DataStore::make_repositories_map(
    snapshots::SnapshotRepository blocks_repository,
    snapshots::SnapshotRepository state_repository_latest,
    snapshots::SnapshotRepository state_repository_historical) {
    datastore::EntityMap<std::unique_ptr<snapshots::SnapshotRepository>> repositories;
    repositories.emplace(blocks::kBlocksRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(blocks_repository)));
    repositories.emplace(state::kStateRepositoryNameLatest, std::make_unique<snapshots::SnapshotRepository>(std::move(state_repository_latest)));
    repositories.emplace(state::kStateRepositoryNameHistorical, std::make_unique<snapshots::SnapshotRepository>(std::move(state_repository_historical)));
    return repositories;
}

}  // namespace silkworm::db
