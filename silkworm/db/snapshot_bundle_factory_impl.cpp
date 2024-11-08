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

#include "snapshot_bundle_factory_impl.hpp"

#include <silkworm/core/common/assert.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/datastore/snapshots/common/snapshot_path.hpp>

namespace silkworm::db {

using namespace snapshots;

SnapshotBundle SnapshotBundleFactoryImpl::make(const std::filesystem::path& dir_path, snapshots::StepRange range) const {
    return SnapshotBundle{
        range,
        make_bundle_data(schema_, dir_path, range),
    };
}

SnapshotBundlePaths SnapshotBundleFactoryImpl::make_paths(const std::filesystem::path& dir_path, snapshots::StepRange range) const {
    return SnapshotBundlePaths{
        schema_,
        dir_path,
        range,
    };
}

std::vector<std::shared_ptr<IndexBuilder>> SnapshotBundleFactoryImpl::index_builders(const SnapshotPath& segment_path) const {
    datastore::EntityName name{segment_path.tag()};
    {
        if (name == db::blocks::kHeaderSegmentName)
            return {std::make_shared<IndexBuilder>(HeaderIndex::make(segment_path))};
        if (name == db::blocks::kBodySegmentName)
            return {std::make_shared<IndexBuilder>(BodyIndex::make(segment_path))};
        if (name == db::blocks::kTxnSegmentName) {
            auto bodies_segment_path = segment_path.related_path(db::blocks::kBodySegmentName.to_string(), db::blocks::kSegmentExtension);
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

std::vector<std::shared_ptr<IndexBuilder>> SnapshotBundleFactoryImpl::index_builders(const SnapshotPathList& segment_paths) const {
    std::vector<std::shared_ptr<IndexBuilder>> all_builders;
    for (const auto& path : segment_paths) {
        auto builders = index_builders(path);
        all_builders.insert(all_builders.end(), builders.begin(), builders.end());
    }
    return all_builders;
}

SnapshotPathList SnapshotBundleFactoryImpl::index_dependency_paths(const SnapshotPath& index_path) const {
    datastore::EntityName name{index_path.tag()};
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
    SnapshotPath snapshot_path = index_path.related_path(segment_name.to_string(), db::blocks::kSegmentExtension);
    return {snapshot_path};
}

}  // namespace silkworm::db
