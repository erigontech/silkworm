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
#include <optional>

#include "../datastore/common/entity_name.hpp"
#include "../datastore/snapshots/index_builders_factory.hpp"
#include "../datastore/snapshots/schema.hpp"
#include "../datastore/snapshots/snapshot_repository.hpp"

namespace silkworm::db::blocks {

inline const datastore::EntityName kBlocksRepositoryName{"Blocks"};

inline constexpr std::string_view kSegmentExtension{".seg"};
inline constexpr std::string_view kIdxExtension{".idx"};

snapshots::Schema::RepositoryDef make_blocks_repository_schema();

std::unique_ptr<snapshots::IndexBuildersFactory> make_blocks_index_builders_factory();

snapshots::SnapshotRepository make_blocks_repository(
    std::filesystem::path dir_path,
    bool open = true,
    std::optional<uint32_t> index_salt = std::nullopt);

inline const datastore::EntityName kHeaderSegmentName{"headers"};
inline constexpr std::string_view kHeaderSegmentTag{"headers"};
//! Index header_hash -> block_num -> headers_segment_offset
inline const datastore::EntityName kIdxHeaderHashName{"headers.idx"};
inline constexpr std::string_view kIdxHeaderHashTag = kHeaderSegmentTag;
inline const snapshots::SegmentAndAccessorIndexNames kHeaderSegmentAndIdxNames{
    snapshots::Schema::kDefaultEntityName,
    kHeaderSegmentName,
    kIdxHeaderHashName,
};

inline const datastore::EntityName kBodySegmentName{"bodies"};
inline constexpr std::string_view kBodySegmentTag{"bodies"};
//! Index block_num -> bodies_segment_offset
inline const datastore::EntityName kIdxBodyNumberName{"bodies.idx"};
inline constexpr std::string_view kIdxBodyNumberTag = kBodySegmentTag;
inline const snapshots::SegmentAndAccessorIndexNames kBodySegmentAndIdxNames{
    snapshots::Schema::kDefaultEntityName,
    kBodySegmentName,
    kIdxBodyNumberName,
};

inline const datastore::EntityName kTxnSegmentName{"transactions"};
inline constexpr std::string_view kTxnSegmentTag{"transactions"};
//! Index transaction_hash -> txn_id -> transactions_segment_offset
inline const datastore::EntityName kIdxTxnHashName{"transactions.idx"};
inline constexpr std::string_view kIdxTxnHashTag = kTxnSegmentTag;
inline const snapshots::SegmentAndAccessorIndexNames kTxnSegmentAndIdxNames{
    snapshots::Schema::kDefaultEntityName,
    kTxnSegmentName,
    kIdxTxnHashName,
};
//! Index transaction_hash -> block_num
inline const datastore::EntityName kIdxTxnHash2BlockName{"transactions-to-block.idx"};
inline constexpr std::string_view kIdxTxnHash2BlockTag{"transactions-to-block"};

struct BundleDataRef {
    const snapshots::SnapshotBundleData& data;
    const snapshots::SnapshotBundleEntityData& entity_data() const { return data.entities.at(snapshots::Schema::kDefaultEntityName); }

    const snapshots::segment::SegmentFileReader& header_segment() const { return entity_data().segments.at(kHeaderSegmentName); }
    const snapshots::rec_split::AccessorIndex& idx_header_hash() const { return entity_data().accessor_indexes.at(kIdxHeaderHashName); }

    const snapshots::segment::SegmentFileReader& body_segment() const { return entity_data().segments.at(kBodySegmentName); }
    const snapshots::rec_split::AccessorIndex& idx_body_number() const { return entity_data().accessor_indexes.at(kIdxBodyNumberName); }

    const snapshots::segment::SegmentFileReader& txn_segment() const { return entity_data().segments.at(kTxnSegmentName); }
    const snapshots::rec_split::AccessorIndex& idx_txn_hash() const { return entity_data().accessor_indexes.at(kIdxTxnHashName); }
    const snapshots::rec_split::AccessorIndex& idx_txn_hash_2_block() const { return entity_data().accessor_indexes.at(kIdxTxnHash2BlockName); }
};

}  // namespace silkworm::db::blocks
