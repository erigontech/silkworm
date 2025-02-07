/*
   Copyright 2025 The Silkworm Authors

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

#include "snapshots.hpp"

#include <silkworm/db/datastore/snapshots/snapshot_bundle.hpp>
#include <silkworm/db/state/schema_config.hpp>

using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::snapshots;

MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

static std::optional<SnapshotPath> parse_snapshot_path(const char* file_path) {
    if (!file_path) return std::nullopt;
    return SnapshotPath::parse(file_path);
}

SnapshotBundleEntityDataResult build_inverted_index_entity_data(const SilkwormInvertedIndexSnapshot& snapshot) {
    const auto ii_segment_path = parse_snapshot_path(snapshot.segment.file_path);
    if (!ii_segment_path) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    segment::KVSegmentFileReader ii_segment{*ii_segment_path, seg::CompressionKind::kNone, make_region(snapshot.segment)};
    const auto ii_accessor_index_path = parse_snapshot_path(snapshot.accessor_index.file_path);
    if (!ii_accessor_index_path) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    rec_split::AccessorIndex ii_accessor_index{*ii_accessor_index_path, make_region(snapshot.accessor_index)};

    SnapshotBundleEntityData data;
    data.kv_segments.emplace(Schema::kInvIdxKVSegmentName, std::move(ii_segment));
    data.accessor_indexes.emplace(Schema::kInvIdxAccessorIndexName, std::move(ii_accessor_index));
    return data;
}

SnapshotBundleEntityDataResult build_domain_entity_data(const SilkwormDomainSnapshot& snapshot, uint32_t salt) {
    // Domain snapshot files
    const auto d_segment_path = parse_snapshot_path(snapshot.segment.file_path);
    if (!d_segment_path) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    segment::KVSegmentFileReader d_segment{*d_segment_path, seg::CompressionKind::kAll, make_region(snapshot.segment)};
    const auto d_existence_index_path = parse_snapshot_path(snapshot.existence_index.file_path);
    if (!d_existence_index_path) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    bloom_filter::BloomFilter d_existence_index{d_existence_index_path->path(), bloom_filter::BloomFilterKeyHasher{salt}};
    const auto d_btree_index_path = parse_snapshot_path(snapshot.btree_index.file_path);
    if (!d_btree_index_path) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    btree::BTreeIndex d_bt_index{d_btree_index_path->path(), make_region(snapshot.btree_index)};
    std::optional<rec_split::AccessorIndex> d_accessor_index;
    if (snapshot.has_accessor_index) {
        const auto d_accessor_index_path = parse_snapshot_path(snapshot.accessor_index.file_path);
        if (!d_accessor_index_path) {
            return tl::make_unexpected(SILKWORM_INVALID_PATH);
        }
        d_accessor_index = rec_split::AccessorIndex{*d_accessor_index_path, make_region(snapshot.accessor_index)};
    }

    // History + InvertedIndex snapshot files (optional)
    std::optional<segment::SegmentFileReader> h_segment;
    std::optional<rec_split::AccessorIndex> h_accessor_index;
    std::optional<SnapshotBundleEntityData> h_inverted_index_bundle_data;
    if (snapshot.has_history) {
        const auto h_segment_path = parse_snapshot_path(snapshot.history.segment.file_path);
        if (!h_segment_path) {
            return tl::make_unexpected(SILKWORM_INVALID_PATH);
        }
        h_segment = segment::SegmentFileReader{*h_segment_path, make_region(snapshot.history.segment)};
        const auto h_accessor_index_path = parse_snapshot_path(snapshot.history.accessor_index.file_path);
        if (!h_accessor_index_path) {
            return tl::make_unexpected(SILKWORM_INVALID_PATH);
        }
        h_accessor_index = rec_split::AccessorIndex{*h_accessor_index_path, make_region(snapshot.history.accessor_index)};
        auto ii_bundle_entity_data = build_inverted_index_entity_data(snapshot.history.inverted_index);
        if (!ii_bundle_entity_data) {
            return tl::make_unexpected(SILKWORM_INVALID_PATH);
        }
        h_inverted_index_bundle_data = std::move(*ii_bundle_entity_data);
    }

    SnapshotBundleEntityData data;
    data.kv_segments.emplace(Schema::kDomainKVSegmentName, std::move(d_segment));
    data.existence_indexes.emplace(Schema::kDomainExistenceIndexName, std::move(d_existence_index));
    data.btree_indexes.emplace(Schema::kDomainBTreeIndexName, std::move(d_bt_index));
    if (snapshot.has_accessor_index) {
        data.accessor_indexes.emplace(Schema::kDomainAccessorIndexName, std::move(*d_accessor_index));
    }
    if (snapshot.has_history) {
        data.segments.emplace(Schema::kHistorySegmentName, std::move(*h_segment));
        data.accessor_indexes.emplace(Schema::kHistoryAccessorIndexName, std::move(*h_accessor_index));
        if (h_inverted_index_bundle_data) {
            data.kv_segments.insert(h_inverted_index_bundle_data->kv_segments.extract(Schema::kInvIdxKVSegmentName));
            data.accessor_indexes.insert(h_inverted_index_bundle_data->accessor_indexes.extract(Schema::kHistoryAccessorIndexName));
        }
    }
    return data;
}

SnapshotBundleResult build_state_snapshot(const SilkwormStateSnapshot* snapshot, uint32_t salt) {
    auto accounts_bundle_entity_data = build_domain_entity_data(snapshot->accounts, salt);
    if (!accounts_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto storage_bundle_entity_data = build_domain_entity_data(snapshot->storage, salt);
    if (!storage_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto code_bundle_entity_data = build_domain_entity_data(snapshot->code, salt);
    if (!code_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto commitment_bundle_entity_data = build_domain_entity_data(snapshot->commitment, salt);
    if (!commitment_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto receipt_bundle_entity_data = build_domain_entity_data(snapshot->receipts, salt);
    if (!receipt_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto log_address_bundle_entity_data = build_inverted_index_entity_data(snapshot->log_addresses);
    if (!log_address_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto log_topic_bundle_entity_data = build_inverted_index_entity_data(snapshot->log_topics);
    if (!log_topic_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto trace_from_bundle_entity_data = build_inverted_index_entity_data(snapshot->traces_from);
    if (!trace_from_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }
    auto trace_to_bundle_entity_data = build_inverted_index_entity_data(snapshot->traces_to);
    if (!trace_to_bundle_entity_data) {
        return tl::make_unexpected(SILKWORM_INVALID_PATH);
    }

    // We *must* extract the step range (value type) here before moving accounts_bundle_entity_data
    const auto& segment_file_reader = accounts_bundle_entity_data->kv_segments.at(Schema::kDomainKVSegmentName);
    const auto step_range = segment_file_reader.path().step_range();

    SnapshotBundleData bundle_data;
    bundle_data.entities.emplace(db::state::kDomainNameAccounts, std::move(*accounts_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameStorage, std::move(*storage_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameCode, std::move(*code_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameCommitment, std::move(*commitment_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameReceipts, std::move(*receipt_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameLogAddress, std::move(*log_address_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameLogTopics, std::move(*log_topic_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameTracesFrom, std::move(*trace_from_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameTracesTo, std::move(*trace_to_bundle_entity_data));

    SnapshotBundle bundle{
        step_range,
        std::move(bundle_data),
    };
    return bundle;
}
