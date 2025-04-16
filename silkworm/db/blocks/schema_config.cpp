// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "schema_config.hpp"

#include "blocks_index_builders_factory.hpp"
#include "step_block_num_converter.hpp"

namespace silkworm::db::blocks {

snapshots::Schema::RepositoryDef make_blocks_repository_schema() {
    snapshots::Schema::RepositoryDef repository_schema;
    repository_schema.index_salt_file_name("salt-blocks.txt");
    repository_schema.step_size(kStepSizeForBlockSnapshots);
    snapshots::Schema::EntityDef& schema = repository_schema.default_entity();

    schema.segment(kHeaderSegmentName)
        .tag(kHeaderSegmentTag)
        .file_ext(kSegmentExtension);
    schema.accessor_index(kIdxHeaderHashName)
        .tag(kIdxHeaderHashTag)
        .file_ext(kIdxExtension);

    schema.segment(kBodySegmentName)
        .tag(kBodySegmentTag)
        .file_ext(kSegmentExtension);
    schema.accessor_index(kIdxBodyNumberName)
        .tag(kIdxBodyNumberTag)
        .file_ext(kIdxExtension);

    schema.segment(kTxnSegmentName)
        .tag(kTxnSegmentTag)
        .file_ext(kSegmentExtension);
    schema.accessor_index(kIdxTxnHashName)
        .tag(kIdxTxnHashTag)
        .file_ext(kIdxExtension);
    schema.accessor_index(kIdxTxnHash2BlockName)
        .tag(kIdxTxnHash2BlockTag)
        .file_ext(kIdxExtension);

    return repository_schema;
}

std::unique_ptr<snapshots::IndexBuildersFactory> make_blocks_index_builders_factory() {
    return std::make_unique<BlocksIndexBuildersFactory>(make_blocks_repository_schema());
}

snapshots::SnapshotRepository make_blocks_repository(
    std::filesystem::path dir_path,
    bool open,
    std::optional<uint32_t> index_salt) {
    auto schema = make_blocks_repository_schema();
    return snapshots::SnapshotRepository{
        kBlocksRepositoryName,
        std::move(dir_path),
        open,
        schema,
        index_salt,
        make_blocks_index_builders_factory(),
        std::nullopt,  // no domain caches
        std::nullopt,  // no inverted index caches
    };
}

}  // namespace silkworm::db::blocks
