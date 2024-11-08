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

#include <cctype>
#include <set>

namespace silkworm::snapshots {

SnapshotPath Schema::SnapshotFileDef::make_path(
    const std::filesystem::path& dir_path,
    StepRange range) const {
    return SnapshotPath::make(dir_path, kSnapshotV1, range, tag(), file_ext());
}

Schema::EntityDef& Schema::EntityDef::tag_override(std::string_view tag) {
    for (auto& entry : file_defs_) {
        entry.second.tag(tag);
    }
    return *this;
}

std::vector<std::string> Schema::EntityDef::file_extensions() const {
    std::set<std::string> results;
    for (const auto& entry : entities())
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

std::optional<datastore::EntityName> Schema::EntityDef::entity_name_by_path(const SnapshotPath& path) const {
    for (const auto& [name, def] : entities()) {
        if (def.make_path(path.base_dir_path(), path.step_range()) == path) {
            return name;
        }
    }
    return std::nullopt;
}

std::optional<std::pair<datastore::EntityName, datastore::EntityName>> Schema::RepositoryDef::entity_name_by_path(const SnapshotPath& path) const {
    for (const auto& [entity_name, def] : entities()) {
        auto name = def.entity_name_by_path(path);
        if (name) {
            return std::make_pair(entity_name, *name);
        }
    }
    return std::nullopt;
}

static std::string name2tag(datastore::EntityName name) {
    auto tag = name.to_string();
    for (char& c : tag)
        c = static_cast<char>(std::tolower(c));
    return tag;
}

Schema::EntityDef Schema::RepositoryDef::make_domain_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    schema.kv_segment(kDomainKVSegmentName)
        .tag(name2tag(name))
        .file_ext(kDomainKVSegmentFileExt);
    schema.rec_split_index(kDomainAccessorIndexName)
        .tag(name2tag(name))
        .file_ext(kDomainAccessorIndexFileExt);
    // TODO: add .kvei and .bt
    define_history_schema(name, schema);
    return schema;
}

Schema::EntityDef Schema::RepositoryDef::make_history_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_history_schema(name, schema);
    return schema;
}

void Schema::RepositoryDef::define_history_schema(datastore::EntityName name, EntityDef& schema) {
    schema.segment(kHistorySegmentName)
        .tag(name2tag(name))
        .file_ext(kHistorySegmentFileExt);
    schema.rec_split_index(kHistoryAccessorIndexName)
        .tag(name2tag(name))
        .file_ext(kHistoryAccessorIndexFileExt);
    define_inverted_index_schema(name, schema);
}

Schema::EntityDef Schema::RepositoryDef::make_inverted_index_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_inverted_index_schema(name, schema);
    return schema;
}

void Schema::RepositoryDef::define_inverted_index_schema(datastore::EntityName name, EntityDef& schema) {
    schema.kv_segment(kInvIdxKVSegmentName)
        .tag(name2tag(name))
        .file_ext(kInvIdxKVSegmentFileExt);
    schema.rec_split_index(kInvIdxAccessorIndexName)
        .tag(name2tag(name))
        .file_ext(kInvIdxAccessorIndexFileExt);
}

}  // namespace silkworm::snapshots
