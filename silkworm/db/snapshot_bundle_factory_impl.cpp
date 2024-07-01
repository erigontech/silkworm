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

#include <cassert>

#include <silkworm/db/bodies/body_index.hpp>
#include <silkworm/db/headers/header_index.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>

namespace silkworm::db {

using namespace snapshots;

SnapshotBundle SnapshotBundleFactoryImpl::make(PathByTypeProvider snapshot_path, PathByTypeProvider index_path) const {
    return SnapshotBundle{
        .header_snapshot = Snapshot(snapshot_path(SnapshotType::headers)),
        .idx_header_hash = Index(index_path(SnapshotType::headers)),

        .body_snapshot = Snapshot(snapshot_path(SnapshotType::bodies)),
        .idx_body_number = Index(index_path(SnapshotType::bodies)),

        .txn_snapshot = Snapshot(snapshot_path(SnapshotType::transactions)),
        .idx_txn_hash = Index(index_path(SnapshotType::transactions)),
        .idx_txn_hash_2_block = Index(index_path(SnapshotType::transactions_to_block)),
    };
}

SnapshotBundle SnapshotBundleFactoryImpl::make(const std::filesystem::path& dir_path, BlockNumRange range) const {
    PathByTypeProvider snapshot_path = [&](silkworm::snapshots::SnapshotType type) {
        return SnapshotPath::from(dir_path, kSnapshotV1, range.first, range.second, type);
    };
    PathByTypeProvider index_path = [&](silkworm::snapshots::SnapshotType type) {
        return SnapshotPath::from(dir_path, kSnapshotV1, range.first, range.second, type, kIdxExtension);
    };
    return make(std::move(snapshot_path), std::move(index_path));
}

std::vector<std::shared_ptr<IndexBuilder>> SnapshotBundleFactoryImpl::index_builders(const SnapshotPath& seg_file) const {
    switch (seg_file.type()) {
        case SnapshotType::headers:
            return {std::make_shared<IndexBuilder>(HeaderIndex::make(seg_file))};
        case SnapshotType::bodies:
            return {std::make_shared<IndexBuilder>(BodyIndex::make(seg_file))};
        case SnapshotType::transactions: {
            auto bodies_segment_path = TransactionIndex::bodies_segment_path(seg_file);
            if (!bodies_segment_path.exists()) return {};
            return {
                std::make_shared<IndexBuilder>(TransactionIndex::make(bodies_segment_path, seg_file)),
                std::make_shared<IndexBuilder>(TransactionToBlockIndex::make(bodies_segment_path, seg_file)),
            };
        }
        default:
            assert(false);
            return {};
    }
}

}  // namespace silkworm::db
