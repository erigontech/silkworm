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

#include "../snapshot_bundle_factory_impl.hpp"

namespace silkworm::db::blocks {

snapshots::Schema::RepositoryDef make_blocks_repository_schema() {
    snapshots::Schema::RepositoryDef schema;
    schema
        .segment(kHeaderSegmentName)
        .rec_split_index(kIdxHeaderHashName)
        .segment(kBodySegmentName)
        .rec_split_index(kIdxBodyNumberName)
        .segment(kTxnSegmentName)
        .rec_split_index(kIdxTxnHashName)
        .rec_split_index(kIdxTxnHash2BlockName);
    return schema;
}

std::unique_ptr<snapshots::SnapshotBundleFactory> make_blocks_bundle_factory() {
    return std::make_unique<db::SnapshotBundleFactoryImpl>(make_blocks_repository_schema());
}

snapshots::SnapshotRepository make_blocks_repository(std::filesystem::path dir_path, bool open) {
    return snapshots::SnapshotRepository{
        std::move(dir_path),
        open,
        std::make_unique<snapshots::StepToBlockNumConverter>(),
        make_blocks_bundle_factory(),
    };
}

}  // namespace silkworm::db::blocks
