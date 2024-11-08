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

#pragma once

#include <optional>

#include "blocks/schema_config.hpp"
#include "datastore/data_store.hpp"
#include "state/schema_config.hpp"

namespace silkworm::db {

struct DataStoreRef {
    RWAccess chaindata;
    snapshots::SnapshotRepository& repository;
};

class DataStore {
  public:
    explicit DataStore(datastore::DataStore store) : store_{std::move(store)} {}
    DataStore(
        mdbx::env_managed chaindata_env,
        snapshots::SnapshotRepository blocks_repository,
        std::optional<snapshots::SnapshotRepository> state_repository = std::nullopt)
        : store_{
              make_schema(state_repository.has_value()),
              std::move(chaindata_env),
              make_repositories_map(std::move(blocks_repository), std::move(state_repository)),
          } {}

    DataStore(
        const EnvConfig& chaindata_env_config,
        std::filesystem::path repository_path)  // NOLINT(performance-unnecessary-value-param)
        : DataStore{
              db::open_env(chaindata_env_config),
              blocks::make_blocks_repository(std::move(repository_path)),
          } {}

    void close() {
        store_.close();
    }

    DataStoreRef ref() const {
        return {store_.chaindata_rw(), store_.repository(blocks::kBlocksRepositoryName)};
    }

    db::ROAccess chaindata() const { return store_.chaindata(); }
    db::RWAccess chaindata_rw() const { return store_.chaindata_rw(); }

  private:
    static datastore::Schema make_schema(bool enabled_state_repository);

    static std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> make_repositories_map(
        snapshots::SnapshotRepository blocks_repository,
        std::optional<snapshots::SnapshotRepository> state_repository) {
        std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories;
        repositories.emplace(blocks::kBlocksRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(blocks_repository)));
        if (state_repository)
            repositories.emplace(state::kStateRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(*state_repository)));
        return repositories;
    }

    datastore::DataStore store_;
};

}  // namespace silkworm::db
