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

#include <magic_enum.hpp>

namespace silkworm::snapshots {

std::map<datastore::EntityName, SnapshotPath> Schema::RepositoryDef::make_segment_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& entry : segment_defs_) {
        auto tag = entry.first.to_string();
        results.emplace(entry.first, SnapshotPath::make(dir_path, kSnapshotV1, range, std::move(tag)));
    }
    return results;
}

std::map<datastore::EntityName, SegmentFileReader> Schema::RepositoryDef::make_segments(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SegmentFileReader> results;
    for (auto& entry : make_segment_paths(dir_path, range)) {
        results.emplace(entry.first, SegmentFileReader{entry.second});
    }
    return results;
}

std::map<datastore::EntityName, SnapshotPath> Schema::RepositoryDef::make_rec_split_index_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, SnapshotPath> results;
    for (auto& entry : rec_split_index_defs_) {
        auto tag = entry.first.to_string();
        results.emplace(entry.first, SnapshotPath::make(dir_path, kSnapshotV1, range, std::move(tag), kIdxExtension));
    }
    return results;
}

std::map<datastore::EntityName, Index> Schema::RepositoryDef::make_rec_split_indexes(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::map<datastore::EntityName, Index> results;
    for (auto& entry : make_rec_split_index_paths(dir_path, range)) {
        results.emplace(entry.first, Index{entry.second});
    }
    return results;
}

std::vector<SnapshotPath> Schema::RepositoryDef::make_all_paths(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    std::vector<SnapshotPath> results;
    for (auto& entry : make_segment_paths(dir_path, range))
        results.push_back(std::move(entry.second));
    for (auto& entry : make_rec_split_index_paths(dir_path, range))
        results.push_back(std::move(entry.second));
    return results;
}

}  // namespace silkworm::snapshots
