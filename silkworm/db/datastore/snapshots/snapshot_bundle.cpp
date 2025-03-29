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

using namespace rec_split;
using namespace segment;
using namespace datastore;

static datastore::EntityMap<SnapshotPath> make_snapshot_paths(
    Schema::SnapshotFileDef::Format format,
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    datastore::EntityMap<SnapshotPath> results;
    for (auto& [name, def] : entity.files()) {
        if (def->format() == format) {
            auto path = def->make_path(dir_path, range);
            results.emplace(name, std::move(path));
        }
    }
    return results;
}

static datastore::EntityMap<SegmentFileReader> open_segments(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    datastore::EntityMap<SegmentFileReader> results;
    for (auto& [name, anyDef] : entity.files()) {
        if (anyDef->format() != Schema::SnapshotFileDef::Format::kSegment) continue;
        auto& def = dynamic_cast<const Schema::SegmentDef&>(*anyDef);
        auto path = def.make_path(dir_path, range);
        results.emplace(name, SegmentFileReader{std::move(path), std::nullopt, def.compression_enabled()});
    }
    return results;
}

static datastore::EntityMap<KVSegmentFileReader> open_kv_segments(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    datastore::EntityMap<KVSegmentFileReader> results;
    for (auto& [name, anyDef] : entity.files()) {
        if (anyDef->format() != Schema::SnapshotFileDef::Format::kKVSegment) continue;
        auto& def = dynamic_cast<const Schema::KVSegmentDef&>(*anyDef);
        auto path = def.make_path(dir_path, range);
        results.emplace(name, KVSegmentFileReader{std::move(path), def.compression_kind()});
    }
    return results;
}

static datastore::EntityMap<AccessorIndex> open_accessor_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    datastore::EntityMap<AccessorIndex> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kAccessorIndex, entity, dir_path, range)) {
        results.emplace(name, AccessorIndex{path});
    }
    return results;
}

static datastore::EntityMap<bloom_filter::BloomFilter> open_existence_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range,
    std::optional<uint32_t> salt) {
    datastore::EntityMap<bloom_filter::BloomFilter> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kExistenceIndex, entity, dir_path, range)) {
        SILK_TRACE << "make_existence_indexes opens " << name.to_string() << " at " << path.filename();
        SILKWORM_ASSERT(salt);
        results.emplace(name, bloom_filter::BloomFilter{path.path(), KeyHasher{*salt}});
    }
    return results;
}

static datastore::EntityMap<btree::BTreeIndex> open_btree_indexes(
    const Schema::EntityDef& entity,
    const std::filesystem::path& dir_path,
    StepRange range) {
    datastore::EntityMap<btree::BTreeIndex> results;
    for (auto& [name, path] : make_snapshot_paths(Schema::SnapshotFileDef::Format::kBTreeIndex, entity, dir_path, range)) {
        SILK_TRACE << "make_btree_indexes opens " << name.to_string() << " at " << path.filename();
        results.emplace(name, btree::BTreeIndex{path.path()});
    }
    return results;
}

SnapshotBundleData open_bundle_data(
    const Schema::RepositoryDef& schema,
    const std::filesystem::path& dir_path,
    StepRange step_range,
    std::optional<uint32_t> index_salt) {
    SnapshotBundleData data;
    for (auto& [name, entity_schema_ptr] : schema.entities()) {
        auto& entity_schema = *entity_schema_ptr;
        data.entities.emplace(
            name,
            SnapshotBundleEntityData{
                open_segments(entity_schema, dir_path, step_range),
                open_kv_segments(entity_schema, dir_path, step_range),
                open_accessor_indexes(entity_schema, dir_path, step_range),
                open_existence_indexes(entity_schema, dir_path, step_range, index_salt),
                open_btree_indexes(entity_schema, dir_path, step_range),
            });
    }
    return data;
}

SnapshotBundle::~SnapshotBundle() {
    close();
}

void SnapshotBundle::close() {
    auto files = this->files();
    data_.entities.clear();
    auto on_close_callback = std::exchange(on_close_callback_, {});
    if (on_close_callback) {
        on_close_callback(std::move(files));
    }
}

const SegmentFileReader& SnapshotBundle::segment(
    datastore::EntityName entity_name,
    datastore::EntityName segment_name) const {
    return data_.entities.at(entity_name).segments.at(segment_name);
}

const AccessorIndex& SnapshotBundle::accessor_index(
    datastore::EntityName entity_name,
    datastore::EntityName index_name) const {
    return data_.entities.at(entity_name).accessor_indexes.at(index_name);
}

Domain SnapshotBundle::domain(datastore::EntityName name) const {
    auto& data = data_.entities.at(name);
    Domain domain{
        data.kv_segments.at(Schema::kDomainKVSegmentName),
        nullptr,
        data.existence_indexes.at(Schema::kDomainExistenceIndexName),
        data.btree_indexes.at(Schema::kDomainBTreeIndexName),
    };
    if (data.accessor_indexes.contains(Schema::kDomainAccessorIndexName)) {
        domain.accessor_index = &data.accessor_indexes.at(Schema::kDomainAccessorIndexName);
    }
    return domain;
}

History SnapshotBundle::history(datastore::EntityName name) const {
    auto& data = data_.entities.at(name);
    return History{
        data.segments.at(Schema::kHistorySegmentName),
        data.accessor_indexes.at(Schema::kHistoryAccessorIndexName),
        inverted_index(name),
    };
}

InvertedIndex SnapshotBundle::inverted_index(datastore::EntityName name) const {
    auto& data = data_.entities.at(name);
    return InvertedIndex{
        data.kv_segments.at(Schema::kInvIdxKVSegmentName),
        data.accessor_indexes.at(Schema::kInvIdxAccessorIndexName),
    };
}

std::vector<std::filesystem::path> SnapshotBundle::files() const {
    std::vector<std::filesystem::path> files;
    for (auto& entity_entry : data_.entities) {
        auto& data = entity_entry.second;
        for (const auto& file : make_map_values_view(data.segments))
            files.push_back(file.fs_path());
        for (const auto& file : make_map_values_view(data.kv_segments))
            files.push_back(file.fs_path());
        for (const auto& file : make_map_values_view(data.accessor_indexes))
            files.push_back(file.fs_path());
        for (const auto& file : make_map_values_view(data.existence_indexes))
            files.push_back(file.path());
        for (const auto& file : make_map_values_view(data.btree_indexes))
            files.push_back(file.path());
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

datastore::EntityMap<SnapshotPath> SnapshotBundlePaths::segment_paths() const {
    auto& entity = *schema_.entities().at(Schema::kDefaultEntityName);
    return make_snapshot_paths(Schema::SnapshotFileDef::Format::kSegment, entity, dir_path_, step_range_);
}

datastore::EntityMap<SnapshotPath> SnapshotBundlePaths::accessor_index_paths() const {
    auto& entity = *schema_.entities().at(Schema::kDefaultEntityName);
    return make_snapshot_paths(Schema::SnapshotFileDef::Format::kAccessorIndex, entity, dir_path_, step_range_);
}

std::vector<std::filesystem::path> SnapshotBundlePaths::files() const {
    std::vector<std::filesystem::path> results;
    for (auto& entity_entry : schema_.entities()) {
        for (auto& file_entry : entity_entry.second->files()) {
            auto path = file_entry.second->make_path(dir_path_, step_range_);
            results.push_back(path.path());
        }
    }
    return results;
}

}  // namespace silkworm::snapshots
