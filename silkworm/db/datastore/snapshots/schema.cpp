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

#include "schema.hpp"

#include <set>

namespace silkworm::snapshots {

std::map<datastore::EntityName, SnapshotPath> Schema::EntityDef::make_segment_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& entry : segment_defs_) {
        auto tag = entry.first.to_string();
        auto& file_ext = entry.second.file_ext();
        results.emplace(entry.first, SnapshotPath::make(dir_path, kSnapshotV1, range, std::move(tag), file_ext));
    }
    return results;
}

std::map<datastore::EntityName, SegmentFileReader> Schema::EntityDef::make_segments(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SegmentFileReader> results;
    for (auto& entry : make_segment_paths(dir_path, range)) {
        results.emplace(entry.first, SegmentFileReader{entry.second});
    }
    return results;
}

std::map<datastore::EntityName, SnapshotPath> Schema::EntityDef::make_kv_segment_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& entry : kv_segment_defs_) {
        auto tag = entry.first.to_string();
        auto& file_ext = entry.second.file_ext();
        results.emplace(entry.first, SnapshotPath::make(dir_path, kSnapshotV1, range, std::move(tag), file_ext));
    }
    return results;
}

std::map<datastore::EntityName, KVSegmentFileReader> Schema::EntityDef::make_kv_segments(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, KVSegmentFileReader> results;
    for (auto& entry : make_kv_segment_paths(dir_path, range)) {
        results.emplace(entry.first, KVSegmentFileReader{entry.second, seg::CompressionKind::kAll});
    }
    return results;
}

std::map<datastore::EntityName, SnapshotPath> Schema::EntityDef::make_rec_split_index_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& entry : rec_split_index_defs_) {
        auto tag = entry.first.to_string();
        auto& file_ext = entry.second.file_ext();
        results.emplace(entry.first, SnapshotPath::make(dir_path, kSnapshotV1, range, std::move(tag), file_ext));
    }
    return results;
}

std::map<datastore::EntityName, Index> Schema::EntityDef::make_rec_split_indexes(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, Index> results;
    for (auto& entry : make_rec_split_index_paths(dir_path, range)) {
        results.emplace(entry.first, Index{entry.second});
    }
    return results;
}

std::vector<SnapshotPath> Schema::EntityDef::make_all_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::vector<SnapshotPath> results;
    for (auto& entry : make_segment_paths(dir_path, range))
        results.push_back(std::move(entry.second));
    for (auto& entry : make_kv_segment_paths(dir_path, range))
        results.push_back(std::move(entry.second));
    for (auto& entry : make_rec_split_index_paths(dir_path, range))
        results.push_back(std::move(entry.second));
    return results;
}

std::vector<std::string> Schema::EntityDef::file_extensions() const {
    std::set<std::string> results;
    for (const auto& entry : segment_defs_)
        results.insert(entry.second.file_ext());
    for (const auto& entry : kv_segment_defs_)
        results.insert(entry.second.file_ext());
    for (const auto& entry : rec_split_index_defs_)
        results.insert(entry.second.file_ext());
    return std::vector<std::string>{results.begin(), results.end()};
}

std::vector<std::string> Schema::RepositoryDef::file_extensions() const {
    std::set<std::string> results;
    for (const auto& entry : entities())
        for (const auto& file_ext : entry.second.file_extensions())
            results.insert(file_ext);
    return std::vector<std::string>{results.begin(), results.end()};
}

Schema::EntityDef Schema::RepositoryDef::make_domain_schema() {
    Schema::EntityDef schema;
    schema.kv_segment(kDomainKVSegmentName).file_ext(kDomainKVSegmentFileExt);
    schema.rec_split_index(kDomainAccessorIndexName).file_ext(kDomainAccessorIndexFileExt);
    // TODO: add .kvei and .bt
    define_history_schema(schema);
    return schema;
}

Schema::EntityDef Schema::RepositoryDef::make_history_schema() {
    Schema::EntityDef schema;
    define_history_schema(schema);
    return schema;
}

void Schema::RepositoryDef::define_history_schema(Schema::EntityDef& schema) {
    schema.segment(kHistorySegmentName).file_ext(kHistorySegmentFileExt);
    schema.rec_split_index(kHistoryAccessorIndexName).file_ext(kHistoryAccessorIndexFileExt);
    define_inverted_index_schema(schema);
}

Schema::EntityDef Schema::RepositoryDef::make_inverted_index_schema() {
    Schema::EntityDef schema;
    define_inverted_index_schema(schema);
    return schema;
}

void Schema::RepositoryDef::define_inverted_index_schema(EntityDef& schema) {
    schema.kv_segment(kInvIdxKVSegmentName).file_ext(kInvIdxKVSegmentFileExt);
    schema.rec_split_index(kInvIdxAccessorIndexName).file_ext(kInvIdxAccessorIndexFileExt);
}

}  // namespace silkworm::snapshots
