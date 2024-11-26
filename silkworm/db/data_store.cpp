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
    snapshots::Schema snapshots;
    snapshots.repository(blocks::kBlocksRepositoryName) = blocks::make_blocks_repository_schema();
    snapshots.repository(state::kStateRepositoryName) = state::make_state_repository_schema();

    return {
        std::move(snapshots),
    };
}

std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> DataStore::make_repositories_map(
    snapshots::SnapshotRepository blocks_repository,
    snapshots::SnapshotRepository state_repository) {
    std::map<datastore::EntityName, std::unique_ptr<snapshots::SnapshotRepository>> repositories;
    repositories.emplace(blocks::kBlocksRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(blocks_repository)));
    repositories.emplace(state::kStateRepositoryName, std::make_unique<snapshots::SnapshotRepository>(std::move(state_repository)));
    return repositories;
}

}  // namespace silkworm::db
