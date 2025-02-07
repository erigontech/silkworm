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

#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/schema_config.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_bundle.hpp>
#include <silkworm/db/state/schema_config.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

#include "instance.hpp"
#include "silkworm.h"

using namespace silkworm;
using namespace silkworm::db;
using namespace silkworm::snapshots;

static MemoryMappedRegion make_region(const SilkwormMemoryMappedFile& mmf) {
    return {mmf.memory_address, mmf.memory_length};
}

class InvalidSnapshotPathException : public std::runtime_error {
  public:
    explicit InvalidSnapshotPathException(const std::string& invalid_path)
        : std::runtime_error{"invalid snapshot path: " + invalid_path} {}
};

static SnapshotPath parse_snapshot_path(const char* file_path) {
    if (file_path) {
        const auto snapshot_path = SnapshotPath::parse(file_path);
        if (snapshot_path) {
            return *snapshot_path;
        }
    }
    throw InvalidSnapshotPathException{file_path ? file_path : "<nullptr>"};
}

static snapshots::SnapshotBundleEntityData build_inverted_index_entity_data(const SilkwormInvertedIndexSnapshot& snapshot) {
    const auto ii_segment_path = parse_snapshot_path(snapshot.segment.file_path);

    segment::KVSegmentFileReader ii_segment{ii_segment_path, seg::CompressionKind::kNone, make_region(snapshot.segment)};
    const auto ii_accessor_index_path = parse_snapshot_path(snapshot.accessor_index.file_path);

    rec_split::AccessorIndex ii_accessor_index{ii_accessor_index_path, make_region(snapshot.accessor_index)};

    SnapshotBundleEntityData data;
    data.kv_segments.emplace(Schema::kInvIdxKVSegmentName, std::move(ii_segment));
    data.accessor_indexes.emplace(Schema::kInvIdxAccessorIndexName, std::move(ii_accessor_index));
    return data;
}

static snapshots::SnapshotBundleEntityData build_domain_entity_data(const SilkwormDomainSnapshot& snapshot, uint32_t salt) {
    // Domain snapshot files
    const auto d_segment_path = parse_snapshot_path(snapshot.segment.file_path);

    segment::KVSegmentFileReader d_segment{d_segment_path, seg::CompressionKind::kAll, make_region(snapshot.segment)};
    const auto d_existence_index_path = parse_snapshot_path(snapshot.existence_index.file_path);

    bloom_filter::BloomFilter d_existence_index{d_existence_index_path.path(), bloom_filter::BloomFilterKeyHasher{salt}};
    const auto d_btree_index_path = parse_snapshot_path(snapshot.btree_index.file_path);

    btree::BTreeIndex d_bt_index{d_btree_index_path.path(), make_region(snapshot.btree_index)};
    std::optional<rec_split::AccessorIndex> d_accessor_index;
    if (snapshot.has_accessor_index) {
        const auto d_accessor_index_path = parse_snapshot_path(snapshot.accessor_index.file_path);

        d_accessor_index = rec_split::AccessorIndex{d_accessor_index_path, make_region(snapshot.accessor_index)};
    }

    // History + InvertedIndex snapshot files (optional)
    std::optional<segment::SegmentFileReader> h_segment;
    std::optional<rec_split::AccessorIndex> h_accessor_index;
    std::optional<SnapshotBundleEntityData> h_inverted_index_bundle_data;
    if (snapshot.has_history) {
        auto h_segment_path = parse_snapshot_path(snapshot.history.segment.file_path);
        h_segment = segment::SegmentFileReader{std::move(h_segment_path), make_region(snapshot.history.segment)};

        auto h_accessor_index_path = parse_snapshot_path(snapshot.history.accessor_index.file_path);
        h_accessor_index = rec_split::AccessorIndex{std::move(h_accessor_index_path), make_region(snapshot.history.accessor_index)};

        auto ii_bundle_entity_data = build_inverted_index_entity_data(snapshot.history.inverted_index);
        h_inverted_index_bundle_data = std::move(ii_bundle_entity_data);
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

static snapshots::SnapshotBundle build_state_snapshot(const SilkwormStateSnapshot* snapshot, uint32_t salt) {
    auto accounts_bundle_entity_data = build_domain_entity_data(snapshot->accounts, salt);
    auto storage_bundle_entity_data = build_domain_entity_data(snapshot->storage, salt);
    auto code_bundle_entity_data = build_domain_entity_data(snapshot->code, salt);
    auto commitment_bundle_entity_data = build_domain_entity_data(snapshot->commitment, salt);
    auto receipt_bundle_entity_data = build_domain_entity_data(snapshot->receipts, salt);
    auto log_address_bundle_entity_data = build_inverted_index_entity_data(snapshot->log_addresses);
    auto log_topic_bundle_entity_data = build_inverted_index_entity_data(snapshot->log_topics);
    auto trace_from_bundle_entity_data = build_inverted_index_entity_data(snapshot->traces_from);
    auto trace_to_bundle_entity_data = build_inverted_index_entity_data(snapshot->traces_to);

    // We *must* extract the step range (value type) here before moving accounts_bundle_entity_data
    const auto& segment_file_reader = accounts_bundle_entity_data.kv_segments.at(Schema::kDomainKVSegmentName);
    const auto step_range = segment_file_reader.path().step_range();

    SnapshotBundleData bundle_data;
    bundle_data.entities.emplace(db::state::kDomainNameAccounts, std::move(accounts_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameStorage, std::move(storage_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameCode, std::move(code_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameCommitment, std::move(commitment_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kDomainNameReceipts, std::move(receipt_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameLogAddress, std::move(log_address_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameLogTopics, std::move(log_topic_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameTracesFrom, std::move(trace_from_bundle_entity_data));
    bundle_data.entities.emplace(db::state::kInvIdxNameTracesTo, std::move(trace_to_bundle_entity_data));

    SnapshotBundle bundle{
        step_range,
        std::move(bundle_data),
    };
    return bundle;
}

SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle handle, struct SilkwormMemoryMappedFile* segments[], size_t len) SILKWORM_NOEXCEPT {
    constexpr int kNeededIndexesToBuildInParallel = 2;

    if (!handle) {
        return SILKWORM_INVALID_HANDLE;
    }

    auto schema = db::blocks::make_blocks_repository_schema();

    std::vector<std::shared_ptr<snapshots::IndexBuilder>> needed_indexes;
    for (size_t i = 0; i < len; ++i) {
        struct SilkwormMemoryMappedFile* segment = segments[i];
        if (!segment) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        auto segment_region = make_region(*segment);

        const auto snapshot_path = snapshots::SnapshotPath::parse(segment->file_path);
        if (!snapshot_path) {
            return SILKWORM_INVALID_PATH;
        }

        auto names = schema.entity_name_by_path(*snapshot_path);
        if (!names) {
            return SILKWORM_INVALID_PATH;
        }
        datastore::EntityName name = names->second;
        {
            if (name == db::blocks::kHeaderSegmentName) {
                auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::HeaderIndex::make(*snapshot_path, segment_region));
                needed_indexes.push_back(index);
            } else if (name == db::blocks::kBodySegmentName) {
                auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::BodyIndex::make(*snapshot_path, segment_region));
                needed_indexes.push_back(index);
            } else if (name == db::blocks::kTxnSegmentName) {
                auto bodies_segment_path = snapshot_path->related_path(std::string{db::blocks::kBodySegmentTag}, db::blocks::kSegmentExtension);
                auto bodies_file = std::find_if(segments, segments + len, [&](SilkwormMemoryMappedFile* file) -> bool {
                    return snapshots::SnapshotPath::parse(file->file_path) == bodies_segment_path;
                });

                if (bodies_file < segments + len) {
                    auto bodies_segment_region = make_region(**bodies_file);

                    auto index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, segment_region));
                    needed_indexes.push_back(index);

                    index = std::make_shared<snapshots::IndexBuilder>(snapshots::TransactionToBlockIndex::make(
                        bodies_segment_path, bodies_segment_region, *snapshot_path, segment_region));
                    needed_indexes.push_back(index);
                }
            } else {
                SILKWORM_ASSERT(false);
            }
        }
    }

    if (needed_indexes.size() < kNeededIndexesToBuildInParallel) {
        // sequential build
        for (const auto& index : needed_indexes) {
            index->build();
        }
    } else {
        // parallel build
        ThreadPool workers;

        // Create worker tasks for missing indexes
        for (const auto& index : needed_indexes) {
            workers.push_task([=]() {
                try {
                    SILK_INFO << "Build index: " << index->path().filename() << " start";
                    index->build();
                    SILK_INFO << "Build index: " << index->path().filename() << " end";
                } catch (const std::exception& ex) {
                    SILK_CRIT << "Build index: " << index->path().filename() << " failed [" << ex.what() << "]";
                }
            });
        }

        // Wait for all missing indexes to be built or stop request
        while (workers.get_tasks_total()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Wait for any already-started-but-unfinished work in case of stop request
        workers.pause();
        workers.wait_for_tasks();
    }

    return SILKWORM_OK;
}

SILKWORM_EXPORT int silkworm_add_blocks_snapshot(SilkwormHandle handle, SilkwormChainSnapshot* snapshot) SILKWORM_NOEXCEPT {
    try {
        if (!handle || !handle->blocks_repository) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!snapshot) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        const SilkwormHeadersSnapshot& hs = snapshot->headers;
        if (!hs.header_hash_index.file_path) {
            return SILKWORM_INVALID_PATH;
        }
        const auto headers_segment_path = parse_snapshot_path(hs.segment.file_path);

        snapshots::segment::SegmentFileReader header_segment{headers_segment_path, make_region(hs.segment)};
        snapshots::rec_split::AccessorIndex idx_header_hash{headers_segment_path.related_path_ext(db::blocks::kIdxExtension), make_region(hs.header_hash_index)};

        const SilkwormBodiesSnapshot& bs = snapshot->bodies;
        if (!bs.block_num_index.file_path) {
            return SILKWORM_INVALID_PATH;
        }
        const auto bodies_segment_path = parse_snapshot_path(bs.segment.file_path);

        snapshots::segment::SegmentFileReader body_segment{bodies_segment_path, make_region(bs.segment)};
        snapshots::rec_split::AccessorIndex idx_body_number{bodies_segment_path.related_path_ext(db::blocks::kIdxExtension), make_region(bs.block_num_index)};

        const SilkwormTransactionsSnapshot& ts = snapshot->transactions;
        if (!ts.tx_hash_index.file_path || !ts.tx_hash_2_block_index.file_path) {
            return SILKWORM_INVALID_PATH;
        }
        const auto transactions_segment_path = parse_snapshot_path(ts.segment.file_path);

        snapshots::segment::SegmentFileReader txn_segment{transactions_segment_path, make_region(ts.segment)};
        snapshots::rec_split::AccessorIndex idx_txn_hash{transactions_segment_path.related_path_ext(db::blocks::kIdxExtension), make_region(ts.tx_hash_index)};
        snapshots::rec_split::AccessorIndex idx_txn_hash_2_block{transactions_segment_path.related_path(std::string{db::blocks::kIdxTxnHash2BlockTag}, db::blocks::kIdxExtension), make_region(ts.tx_hash_2_block_index)};

        auto bundle_data_provider = [&]() -> snapshots::SnapshotBundleEntityData {
            snapshots::SnapshotBundleEntityData data;

            data.segments.emplace(db::blocks::kHeaderSegmentName, std::move(header_segment));
            data.accessor_indexes.emplace(db::blocks::kIdxHeaderHashName, std::move(idx_header_hash));

            data.segments.emplace(db::blocks::kBodySegmentName, std::move(body_segment));
            data.accessor_indexes.emplace(db::blocks::kIdxBodyNumberName, std::move(idx_body_number));

            data.segments.emplace(db::blocks::kTxnSegmentName, std::move(txn_segment));
            data.accessor_indexes.emplace(db::blocks::kIdxTxnHashName, std::move(idx_txn_hash));
            data.accessor_indexes.emplace(db::blocks::kIdxTxnHash2BlockName, std::move(idx_txn_hash_2_block));

            return data;
        };
        snapshots::SnapshotBundleData bundle_data;
        bundle_data.entities.emplace(snapshots::Schema::kDefaultEntityName, bundle_data_provider());

        snapshots::SnapshotBundle bundle{
            headers_segment_path.step_range(),
            std::move(bundle_data),
        };
        handle->blocks_repository->add_snapshot_bundle(std::move(bundle));

        return SILKWORM_OK;
    } catch (const InvalidSnapshotPathException&) {
        return SILKWORM_INVALID_PATH;
    } catch (...) {
        return SILKWORM_INTERNAL_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_add_state_snapshot(SilkwormHandle handle, const SilkwormStateSnapshot* snapshot) SILKWORM_NOEXCEPT {
    try {
        if (!handle || !handle->state_repository) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!snapshot) {
            return SILKWORM_INVALID_SNAPSHOT;
        }
        if (!handle->state_repository->index_salt()) {
            return SILKWORM_INTERNAL_ERROR;
        }

        auto snapshot_bundle = build_state_snapshot(snapshot, *handle->state_repository->index_salt());
        handle->state_repository->add_snapshot_bundle(std::move(snapshot_bundle));

        return SILKWORM_OK;
    } catch (const InvalidSnapshotPathException&) {
        return SILKWORM_INVALID_PATH;
    } catch (...) {
        return SILKWORM_INTERNAL_ERROR;
    }
}
