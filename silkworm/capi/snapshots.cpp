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

static void build_inverted_index_bundle_data(
    const SilkwormInvertedIndexSnapshot& snapshot,
    const Schema::EntityDef& entity_def,
    SnapshotBundleEntityData& data) {
    data.kv_segments.emplace(
        Schema::kInvIdxKVSegmentName,
        segment::KVSegmentFileReader{
            parse_snapshot_path(snapshot.segment.file_path),
            entity_def.kv_segment(Schema::kInvIdxKVSegmentName).compression_kind(),
            make_region(snapshot.segment),
        });
    data.accessor_indexes.emplace(
        Schema::kInvIdxAccessorIndexName,
        rec_split::AccessorIndex{
            parse_snapshot_path(snapshot.accessor_index.file_path),
            make_region(snapshot.accessor_index),
        });
}

static snapshots::SnapshotBundleEntityData build_inverted_index_bundle_data(
    const SilkwormInvertedIndexSnapshot& snapshot,
    const Schema::EntityDef& entity_def) {
    SnapshotBundleEntityData data;
    build_inverted_index_bundle_data(snapshot, entity_def, data);
    return data;
}

static snapshots::SnapshotBundleEntityData build_domain_bundle_data(
    const SilkwormDomainSnapshot& snapshot,
    const Schema::EntityDef& entity_def,
    uint32_t index_salt) {
    SnapshotBundleEntityData data;
    data.kv_segments.emplace(
        Schema::kDomainKVSegmentName,
        segment::KVSegmentFileReader{
            parse_snapshot_path(snapshot.segment.file_path),
            entity_def.kv_segment(Schema::kDomainKVSegmentName).compression_kind(),
            make_region(snapshot.segment),
        });
    data.existence_indexes.emplace(
        Schema::kDomainExistenceIndexName,
        bloom_filter::BloomFilter{
            parse_snapshot_path(snapshot.existence_index.file_path).path(),
            bloom_filter::BloomFilterKeyHasher{index_salt},
        });
    data.btree_indexes.emplace(
        Schema::kDomainBTreeIndexName,
        btree::BTreeIndex{
            parse_snapshot_path(snapshot.btree_index.file_path).path(),
            make_region(snapshot.btree_index),
        });
    if (snapshot.has_accessor_index) {
        data.accessor_indexes.emplace(
            Schema::kDomainAccessorIndexName,
            rec_split::AccessorIndex{
                parse_snapshot_path(snapshot.accessor_index.file_path),
                make_region(snapshot.accessor_index),
            });
    }
    return data;
}

static snapshots::SnapshotBundleEntityData build_history_bundle_data(
    const SilkwormHistorySnapshot& snapshot,
    const Schema::EntityDef& entity_def) {
    SnapshotBundleEntityData data;
    data.segments.emplace(
        Schema::kHistorySegmentName,
        segment::SegmentFileReader{
            parse_snapshot_path(snapshot.segment.file_path),
            make_region(snapshot.segment),
        });
    data.accessor_indexes.emplace(
        Schema::kHistoryAccessorIndexName,
        rec_split::AccessorIndex{
            parse_snapshot_path(snapshot.accessor_index.file_path),
            make_region(snapshot.accessor_index),
        });

    build_inverted_index_bundle_data(snapshot.inverted_index, entity_def, data);
    return data;
}

static snapshots::SnapshotBundle build_state_snapshot_bundle_latest(
    const SilkwormStateSnapshotBundleLatest* bundle,
    const Schema::RepositoryDef& schema,
    uint32_t salt) {
    SnapshotBundleData bundle_data;
    bundle_data.entities.emplace(
        db::state::kDomainNameAccounts,
        build_domain_bundle_data(bundle->accounts, schema.domain(db::state::kDomainNameAccounts), salt));
    bundle_data.entities.emplace(
        db::state::kDomainNameStorage,
        build_domain_bundle_data(bundle->storage, schema.domain(db::state::kDomainNameStorage), salt));
    bundle_data.entities.emplace(
        db::state::kDomainNameCode,
        build_domain_bundle_data(bundle->code, schema.domain(db::state::kDomainNameCode), salt));
    // TODO(canepat): enable after fixing .kvi configuration with IndexList-like implementation
    // bundle_data.entities.emplace(
    //     db::state::kDomainNameCommitment,
    //     build_domain_bundle_data(bundle->commitment, schema.domain(db::state::kDomainNameCommitment), salt));
    bundle_data.entities.emplace(
        db::state::kDomainNameReceipts,
        build_domain_bundle_data(bundle->receipts, schema.domain(db::state::kDomainNameReceipts), salt));

    return SnapshotBundle{
        parse_snapshot_path(bundle->accounts.segment.file_path).step_range(),
        std::move(bundle_data),
    };
}

static snapshots::SnapshotBundle build_state_snapshot_bundle_historical(
    const SilkwormStateSnapshotBundleHistorical* bundle,
    const Schema::RepositoryDef& schema) {
    SnapshotBundleData bundle_data;

    bundle_data.entities.emplace(
        db::state::kDomainNameAccounts,
        build_history_bundle_data(bundle->accounts, schema.history(db::state::kDomainNameAccounts)));
    bundle_data.entities.emplace(
        db::state::kDomainNameStorage,
        build_history_bundle_data(bundle->storage, schema.history(db::state::kDomainNameStorage)));
    bundle_data.entities.emplace(
        db::state::kDomainNameCode,
        build_history_bundle_data(bundle->code, schema.history(db::state::kDomainNameCode)));
    bundle_data.entities.emplace(
        db::state::kDomainNameReceipts,
        build_history_bundle_data(bundle->receipts, schema.history(db::state::kDomainNameReceipts)));

    bundle_data.entities.emplace(
        db::state::kInvIdxNameLogAddress,
        build_inverted_index_bundle_data(bundle->log_addresses, schema.inverted_index(db::state::kInvIdxNameLogAddress)));
    bundle_data.entities.emplace(
        db::state::kInvIdxNameLogTopics,
        build_inverted_index_bundle_data(bundle->log_topics, schema.inverted_index(db::state::kInvIdxNameLogTopics)));
    bundle_data.entities.emplace(
        db::state::kInvIdxNameTracesFrom,
        build_inverted_index_bundle_data(bundle->traces_from, schema.inverted_index(db::state::kInvIdxNameTracesFrom)));
    bundle_data.entities.emplace(
        db::state::kInvIdxNameTracesTo,
        build_inverted_index_bundle_data(bundle->traces_to, schema.inverted_index(db::state::kInvIdxNameTracesTo)));

    return SnapshotBundle{
        parse_snapshot_path(bundle->accounts.segment.file_path).step_range(),
        std::move(bundle_data),
    };
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

static snapshots::SnapshotBundle build_blocks_snapshot_bundle(const SilkwormBlocksSnapshotBundle* bundle) {
    snapshots::SnapshotBundleEntityData data;

    data.segments.emplace(
        db::blocks::kHeaderSegmentName,
        snapshots::segment::SegmentFileReader{
            parse_snapshot_path(bundle->headers.segment.file_path),
            make_region(bundle->headers.segment),
        });
    data.accessor_indexes.emplace(
        db::blocks::kIdxHeaderHashName,
        snapshots::rec_split::AccessorIndex{
            parse_snapshot_path(bundle->headers.header_hash_index.file_path),
            make_region(bundle->headers.header_hash_index),
        });

    data.segments.emplace(
        db::blocks::kBodySegmentName,
        snapshots::segment::SegmentFileReader{
            parse_snapshot_path(bundle->bodies.segment.file_path),
            make_region(bundle->bodies.segment),
        });
    data.accessor_indexes.emplace(
        db::blocks::kIdxBodyNumberName,
        snapshots::rec_split::AccessorIndex{
            parse_snapshot_path(bundle->bodies.block_num_index.file_path),
            make_region(bundle->bodies.block_num_index),
        });

    data.segments.emplace(
        db::blocks::kTxnSegmentName,
        snapshots::segment::SegmentFileReader{
            parse_snapshot_path(bundle->transactions.segment.file_path),
            make_region(bundle->transactions.segment),
        });
    data.accessor_indexes.emplace(
        db::blocks::kIdxTxnHashName,
        snapshots::rec_split::AccessorIndex{
            parse_snapshot_path(bundle->transactions.tx_hash_index.file_path),
            make_region(bundle->transactions.tx_hash_index),
        });
    data.accessor_indexes.emplace(
        db::blocks::kIdxTxnHash2BlockName,
        snapshots::rec_split::AccessorIndex{
            parse_snapshot_path(bundle->transactions.tx_hash_2_block_index.file_path),
            make_region(bundle->transactions.tx_hash_2_block_index),
        });

    snapshots::SnapshotBundleData bundle_data;
    bundle_data.entities.emplace(snapshots::Schema::kDefaultEntityName, std::move(data));

    return snapshots::SnapshotBundle{
        parse_snapshot_path(bundle->headers.segment.file_path).step_range(),
        std::move(bundle_data),
    };
}

SILKWORM_EXPORT int silkworm_add_blocks_snapshot_bundle(
    SilkwormHandle handle,
    const SilkwormBlocksSnapshotBundle* bundle) SILKWORM_NOEXCEPT {
    try {
        if (!handle || !handle->blocks_repository) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!bundle) {
            return SILKWORM_INVALID_SNAPSHOT;
        }

        auto& repository = *handle->blocks_repository;

        repository.add_snapshot_bundle(build_blocks_snapshot_bundle(bundle));
        return SILKWORM_OK;
    } catch (const InvalidSnapshotPathException&) {
        return SILKWORM_INVALID_PATH;
    } catch (...) {
        return SILKWORM_INTERNAL_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_add_state_snapshot_bundle_latest(
    SilkwormHandle handle,
    const SilkwormStateSnapshotBundleLatest* bundle) SILKWORM_NOEXCEPT {
    try {
        if (!handle || !handle->state_repository_latest) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!bundle) {
            return SILKWORM_INVALID_SNAPSHOT;
        }

        auto& repository = *handle->state_repository_latest;
        if (!repository.index_salt()) {
            return SILKWORM_INTERNAL_ERROR;
        }

        repository.add_snapshot_bundle(build_state_snapshot_bundle_latest(bundle, repository.schema(), *repository.index_salt()));
        return SILKWORM_OK;
    } catch (const InvalidSnapshotPathException&) {
        return SILKWORM_INVALID_PATH;
    } catch (...) {
        return SILKWORM_INTERNAL_ERROR;
    }
}

SILKWORM_EXPORT int silkworm_add_state_snapshot_bundle_historical(
    SilkwormHandle handle,
    const SilkwormStateSnapshotBundleHistorical* bundle) SILKWORM_NOEXCEPT {
    try {
        if (!handle || !handle->state_repository_historical) {
            return SILKWORM_INVALID_HANDLE;
        }
        if (!bundle) {
            return SILKWORM_INVALID_SNAPSHOT;
        }

        auto& repository = *handle->state_repository_historical;

        repository.add_snapshot_bundle(build_state_snapshot_bundle_historical(bundle, repository.schema()));
        return SILKWORM_OK;
    } catch (const InvalidSnapshotPathException&) {
        return SILKWORM_INVALID_PATH;
    } catch (...) {
        return SILKWORM_INTERNAL_ERROR;
    }
}
