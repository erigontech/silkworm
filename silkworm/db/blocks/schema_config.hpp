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

#include <memory>

#include "../datastore/common/entity_name.hpp"
#include "../datastore/snapshots/index_builders_factory.hpp"
#include "../datastore/snapshots/schema.hpp"
#include "../datastore/snapshots/snapshot_repository.hpp"

namespace silkworm::db::blocks {

inline constexpr datastore::EntityName kBlocksRepositoryName{"Blocks"};

inline constexpr std::string_view kSegmentExtension{".seg"};
inline constexpr std::string_view kIdxExtension{".idx"};

snapshots::Schema::RepositoryDef make_blocks_repository_schema();

std::unique_ptr<snapshots::IndexBuildersFactory> make_blocks_index_builders_factory();

snapshots::SnapshotRepository make_blocks_repository(
    std::filesystem::path dir_path,
    bool open = true);

inline constexpr datastore::EntityName kHeaderSegmentName{"headers"};
//! Index header_hash -> block_num -> headers_segment_offset
inline constexpr datastore::EntityName kIdxHeaderHashName{"headers"};

inline constexpr datastore::EntityName kBodySegmentName{"bodies"};
//! Index block_num -> bodies_segment_offset
inline constexpr datastore::EntityName kIdxBodyNumberName{"bodies"};

inline constexpr datastore::EntityName kTxnSegmentName{"transactions"};
//! Index transaction_hash -> txn_id -> transactions_segment_offset
inline constexpr datastore::EntityName kIdxTxnHashName{"transactions"};
//! Index transaction_hash -> block_num
inline constexpr datastore::EntityName kIdxTxnHash2BlockName{"transactions-to-block"};

struct BundleDataRef {
    const snapshots::SnapshotBundleData& data;

    const snapshots::SegmentFileReader& header_segment() const { return data.segments.at(kHeaderSegmentName); }
    const snapshots::Index& idx_header_hash() const { return data.rec_split_indexes.at(kIdxHeaderHashName); }

    const snapshots::SegmentFileReader& body_segment() const { return data.segments.at(kBodySegmentName); }
    const snapshots::Index& idx_body_number() const { return data.rec_split_indexes.at(kIdxBodyNumberName); }

    const snapshots::SegmentFileReader& txn_segment() const { return data.segments.at(kTxnSegmentName); }
    const snapshots::Index& idx_txn_hash() const { return data.rec_split_indexes.at(kIdxTxnHashName); }
    const snapshots::Index& idx_txn_hash_2_block() const { return data.rec_split_indexes.at(kIdxTxnHash2BlockName); }
};

}  // namespace silkworm::db::blocks
