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

#include "blocks/schema_config.hpp"
#include "datastore/data_store.hpp"
#include "state/schema_config.hpp"

namespace silkworm::db {

struct DataStoreRef {
    mdbx::env chaindata_env;
    snapshots::SnapshotRepository& repository;
};

class DataStore {
  public:
    explicit DataStore(datastore::DataStore store) : store_{std::move(store)} {}
    DataStore(
        mdbx::env_managed chaindata_env,
        snapshots::SnapshotRepository blocks_repository,
        snapshots::SnapshotRepository state_repository)
        : store_{
              std::move(chaindata_env),
              make_repositories_map(std::move(blocks_repository), std::move(state_repository)),
          } {}

    DataStoreRef ref() const {
        return {store_.chaindata_env(), store_.repository(blocks::kBlocksRepositoryName)};
    }

  private:
    static std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> make_repositories_map(
        snapshots::SnapshotRepository blocks_repository,
        snapshots::SnapshotRepository state_repository) {
        std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories;
        repositories.emplace(blocks::kBlocksRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(blocks_repository)));
        repositories.emplace(state::kStateRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(state_repository)));
        return repositories;
    }

    datastore::DataStore store_;
};

}  // namespace silkworm::db
