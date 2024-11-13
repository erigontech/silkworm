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

#include "blocks_index_builders_factory.hpp"

namespace silkworm::db::blocks {

snapshots::Schema::RepositoryDef make_blocks_repository_schema() {
    snapshots::Schema::RepositoryDef repository_schema;
    snapshots::Schema::EntityDef& schema = repository_schema.default_entity();

    schema.segment(kHeaderSegmentName)
        .tag(kHeaderSegmentTag)
        .file_ext(kSegmentExtension);
    schema.rec_split_index(kIdxHeaderHashName)
        .tag(kIdxHeaderHashTag)
        .file_ext(kIdxExtension);

    schema.segment(kBodySegmentName)
        .tag(kBodySegmentTag)
        .file_ext(kSegmentExtension);
    schema.rec_split_index(kIdxBodyNumberName)
        .tag(kIdxBodyNumberTag)
        .file_ext(kIdxExtension);

    schema.segment(kTxnSegmentName)
        .tag(kTxnSegmentTag)
        .file_ext(kSegmentExtension);
    schema.rec_split_index(kIdxTxnHashName)
        .tag(kIdxTxnHashTag)
        .file_ext(kIdxExtension);
    schema.rec_split_index(kIdxTxnHash2BlockName)
        .tag(kIdxTxnHash2BlockTag)
        .file_ext(kIdxExtension);

    return repository_schema;
}

std::unique_ptr<snapshots::IndexBuildersFactory> make_blocks_index_builders_factory() {
    return std::make_unique<BlocksIndexBuildersFactory>(make_blocks_repository_schema());
}

snapshots::SnapshotRepository make_blocks_repository(std::filesystem::path dir_path, bool open) {
    return snapshots::SnapshotRepository{
        std::move(dir_path),
        open,
        make_blocks_repository_schema(),
        std::make_unique<snapshots::StepToBlockNumConverter>(),
        make_blocks_index_builders_factory(),
    };
}

}  // namespace silkworm::db::blocks
