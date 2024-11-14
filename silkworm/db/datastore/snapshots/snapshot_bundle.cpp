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

#include "snapshot_bundle.hpp"

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::snapshots {

static std::map<datastore::EntityName, SnapshotPath> make_snapshot_paths(
    Schema::SnapshotFileDef::Format format,
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& [name, def] : entity.entities()) {
        if (def.format() == format) {
            auto path = def.make_path(dir_path, range);
            results.emplace(name, std::move(path));
        }
    }
    return results;
}

static std::map<datastore::EntityName, SegmentFileReader> make_segments(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, SegmentFileReader> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kSegment, entity, dir_path, range)) {
        results.emplace(name, SegmentFileReader{path});
    }
    return results;
}

std::map<datastore::EntityName, KVSegmentFileReader> make_kv_segments(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, KVSegmentFileReader> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kKVSegment, entity, dir_path, range)) {
        results.emplace(name, KVSegmentFileReader{path, seg::CompressionKind::kAll});
    }
    return results;
}

std::map<datastore::EntityName, Index> make_rec_split_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, Index> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kRecSplitIndex, entity, dir_path, range)) {
        results.emplace(name, Index{path});
    }
    return results;
}

std::map<datastore::EntityName, bloom_filter::BloomFilter> make_existence_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, bloom_filter::BloomFilter> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kExistenceIndex, entity, dir_path, range)) {
        SILK_TRACE << "make_existence_indexes opens " << name.to_string() << " at " << path.filename();
        // TODO: wait for RAII refactoring
        // results.emplace(name, bloom_filter::BloomFilter{path.path()});
    }
    return results;
}

std::map<datastore::EntityName, btree::BTreeIndex> make_btree_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    std::map<datastore::EntityName, btree::BTreeIndex> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kBTreeIndex, entity, dir_path, range)) {
        SILK_TRACE << "make_btree_indexes opens " << name.to_string() << " at " << path.filename();
        // TODO: refactor to not require Decompressor, wait for RAII refactoring
        // results.emplace(name, btree::BTreeIndex{?, path.path()});
    }
    return results;
}

SnapshotBundleData make_bundle_data(
    const Schema::RepositoryDef& schema,
    const std::filesystem::path& dir_path,
    StepRange step_range) {
    SnapshotBundleData data;
    for (auto& [name, entity_schema] : schema.entities()) {
        data.entities.emplace(
            name,
            SnapshotBundleEntityData{
                make_segments(entity_schema, dir_path, step_range),
                make_kv_segments(entity_schema, dir_path, step_range),
                make_rec_split_indexes(entity_schema, dir_path, step_range),
                make_existence_indexes(entity_schema, dir_path, step_range),
                make_btree_indexes(entity_schema, dir_path, step_range),
            });
    };
    return data;
}

SnapshotBundle::~SnapshotBundle() {
    close();
}

void SnapshotBundle::reopen() {
    for (auto& entity_entry : data_.entities) {
        auto& data = entity_entry.second;
        for (auto& entry : data.segments) {
            SegmentFileReader& segment = entry.second;
            segment.reopen_segment();
            ensure(!segment.empty(), [&]() {
                return "invalid empty snapshot " + segment.fs_path().string();
            });
        }
        for (auto& entry : data.kv_segments) {
            KVSegmentFileReader& segment = entry.second;
            segment.reopen_segment();
            ensure(!segment.empty(), [&]() {
                return "invalid empty snapshot " + segment.fs_path().string();
            });
        }
        for (auto& entry : data.rec_split_indexes) {
            Index& index = entry.second;
            index.reopen_index();
        }
    }
}

void SnapshotBundle::close() {
    for (auto& entity_entry : data_.entities) {
        auto& data = entity_entry.second;
        for (auto& entry : data.rec_split_indexes) {
            Index& index = entry.second;
            index.close_index();
        }
        for (auto& entry : data.segments) {
            SegmentFileReader& segment = entry.second;
            segment.close();
        }
        for (auto& entry : data.kv_segments) {
            KVSegmentFileReader& segment = entry.second;
            segment.close();
        }
    }
    if (on_close_callback_) {
        on_close_callback_(*this);
    }
}

const SegmentFileReader& SnapshotBundle::segment(datastore::EntityName name) const {
    return data_.entities.at(Schema::kDefaultEntityName).segments.at(name);
}

const Index& SnapshotBundle::rec_split_index(datastore::EntityName name) const {
    return data_.entities.at(Schema::kDefaultEntityName).rec_split_indexes.at(name);
}

Domain SnapshotBundle::domain(datastore::EntityName name) const {
    auto& data = data_.entities.at(name);
    Domain domain{
        data.kv_segments.at(Schema::kDomainKVSegmentName),
        data.rec_split_indexes.at(Schema::kDomainAccessorIndexName),
        // TODO: bt & kvei
    };
    if (data.segments.contains(Schema::kHistorySegmentName)) {
        domain.history.emplace(History{
            data.segments.at(Schema::kHistorySegmentName),
            data.rec_split_indexes.at(Schema::kHistoryAccessorIndexName),
            InvertedIndex{
                data.kv_segments.at(Schema::kInvIdxKVSegmentName),
                data.rec_split_indexes.at(Schema::kInvIdxAccessorIndexName),
            },
        });
    }
    return domain;
}

InvertedIndex SnapshotBundle::inverted_index(datastore::EntityName name) const {
    auto& data = data_.entities.at(name);
    return {
        data.kv_segments.at(Schema::kInvIdxKVSegmentName),
        data.rec_split_indexes.at(Schema::kInvIdxAccessorIndexName),
    };
}

std::vector<std::filesystem::path> SnapshotBundle::files() const {
    std::vector<std::filesystem::path> files;
    for (auto& entity_entry : data_.entities) {
        auto& data = entity_entry.second;
        for (const SegmentFileReader& segment : make_map_values_view(data.segments)) {
            files.push_back(segment.path().path());
        }
        for (const KVSegmentFileReader& segment : make_map_values_view(data.kv_segments)) {
            files.push_back(segment.path().path());
        }
        for (const Index& index : make_map_values_view(data.rec_split_indexes)) {
            files.push_back(index.path().path());
        }
    }
    return files;
}

std::vector<SnapshotPath> SnapshotBundle::segment_paths() const {
    std::vector<SnapshotPath> paths;
    for (const SegmentFileReader& segment : segments()) {
        paths.push_back(segment.path());
    }
    return paths;
}

std::map<datastore::EntityName, SnapshotPath> SnapshotBundlePaths::segment_paths() const {
    auto& entity = schema_.entities().at(Schema::kDefaultEntityName);
    return make_snapshot_paths(Schema::SnapshotFileDef::Format::kSegment, entity, dir_path_, step_range_);
}

std::map<datastore::EntityName, SnapshotPath> SnapshotBundlePaths::rec_split_index_paths() const {
    auto& entity = schema_.entities().at(Schema::kDefaultEntityName);
    return make_snapshot_paths(Schema::SnapshotFileDef::Format::kRecSplitIndex, entity, dir_path_, step_range_);
}

std::vector<std::filesystem::path> SnapshotBundlePaths::files() const {
    std::vector<std::filesystem::path> results;
    for (auto& entity_entry : schema_.entities()) {
        for (auto& file_entry : entity_entry.second.entities()) {
            auto path = file_entry.second.make_path(dir_path_, step_range_);
            results.push_back(path.path());
        }
    }
    return results;
}

}  // namespace silkworm::snapshots
