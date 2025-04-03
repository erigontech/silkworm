// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "blocks_index_builders_factory.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/datastore/snapshots/common/snapshot_path.hpp>

namespace silkworm::db::blocks {

using namespace snapshots;

std::vector<std::shared_ptr<IndexBuilder>> BlocksIndexBuildersFactory::index_builders(const SnapshotPath& segment_path) const {
    auto names = schema_.entity_name_by_path(segment_path);
    if (!names) {
        SILKWORM_ASSERT(false);
        return {};
    }
    datastore::EntityName name = names->second;
    {
        if (name == db::blocks::kHeaderSegmentName)
            return {std::make_shared<IndexBuilder>(HeaderIndex::make(segment_path))};
        if (name == db::blocks::kBodySegmentName)
            return {std::make_shared<IndexBuilder>(BodyIndex::make(segment_path))};
        if (name == db::blocks::kTxnSegmentName) {
            auto bodies_segment_path = segment_path.related_path(std::string{db::blocks::kBodySegmentTag}, db::blocks::kSegmentExtension);
            if (!bodies_segment_path.exists()) return {};
            return {
                std::make_shared<IndexBuilder>(TransactionIndex::make(bodies_segment_path, segment_path)),
                std::make_shared<IndexBuilder>(TransactionToBlockIndex::make(bodies_segment_path, segment_path)),
            };
        }
        SILKWORM_ASSERT(false);
        return {};
    }
}

SnapshotPathList BlocksIndexBuildersFactory::index_dependency_paths(const SnapshotPath& index_path) const {
    auto names = schema_.entity_name_by_path(index_path);
    if (!names) {
        SILKWORM_ASSERT(false);
        std::abort();
    }
    datastore::EntityName name = names->second;
    datastore::EntityName segment_name = [name]() -> datastore::EntityName {
        if (name == db::blocks::kIdxHeaderHashName)
            return db::blocks::kHeaderSegmentName;
        if (name == db::blocks::kIdxBodyNumberName)
            return db::blocks::kBodySegmentName;
        if (name == db::blocks::kIdxTxnHashName)
            return db::blocks::kTxnSegmentName;
        if (name == db::blocks::kIdxTxnHash2BlockName)
            return db::blocks::kTxnSegmentName;
        SILKWORM_ASSERT(false);
        std::abort();
    }();
    auto& segment_tag = schema_.entities().at(Schema::kDefaultEntityName)->files().at(segment_name)->tag();
    SnapshotPath snapshot_path = index_path.related_path(segment_tag, db::blocks::kSegmentExtension);
    return {snapshot_path};
}

}  // namespace silkworm::db::blocks
