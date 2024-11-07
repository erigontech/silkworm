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

#include "schema_config.hpp"

#include "state_index_builders_factory.hpp"

namespace silkworm::db::state {

snapshots::Schema::RepositoryDef make_state_repository_schema() {
    snapshots::Schema::RepositoryDef schema;
    return schema;
}

std::unique_ptr<snapshots::IndexBuildersFactory> make_state_index_builders_factory() {
    return std::make_unique<StateIndexBuildersFactory>(make_state_repository_schema());
}

snapshots::SnapshotRepository make_state_repository(std::filesystem::path dir_path, bool open) {
    return snapshots::SnapshotRepository{
        std::move(dir_path),
        open,
        make_state_repository_schema(),
        std::make_unique<snapshots::StepToTxnIdConverter>(),
        make_state_index_builders_factory(),
    };
}

}  // namespace silkworm::db::state
