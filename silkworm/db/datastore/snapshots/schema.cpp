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
    datastore::StepRange range) const {
    auto filename_format = sub_dir_name() ? SnapshotPath::FilenameFormat::kE3 : SnapshotPath::FilenameFormat::kE2;
    return SnapshotPath::make(dir_path, sub_dir_name(), filename_format, kSnapshotV1, range, tag(), file_ext());
}

Schema::EntityDef& Schema::EntityDef::tag_override(std::string_view tag) {
    for (auto& entry : file_defs_) {
        entry.second->tag(tag);
    }
    return *this;
}

std::vector<std::string> Schema::EntityDef::file_extensions() const {
    std::set<std::string> results;
    for (const auto& entry : files())
        results.insert(entry.second->file_ext());
    return std::vector<std::string>{results.begin(), results.end()};
}

std::vector<std::string> Schema::RepositoryDef::file_extensions() const {
    std::set<std::string> results;
    for (const auto& entry : entities())
        for (const auto& file_ext : entry.second->file_extensions())
            results.insert(file_ext);
    return std::vector<std::string>{results.begin(), results.end()};
}

std::optional<datastore::EntityName> Schema::EntityDef::entity_name_by_path(const SnapshotPath& path) const {
    for (const auto& [name, def] : files()) {
        if (def->make_path(path.base_dir_path(), path.step_range()) == path) {
            return name;
        }
    }
    return std::nullopt;
}

std::optional<std::pair<datastore::EntityName, datastore::EntityName>> Schema::RepositoryDef::entity_name_by_path(const SnapshotPath& path) const {
    for (const auto& [entity_name, def] : entities()) {
        auto name = def->entity_name_by_path(path);
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

Schema::DomainDef Schema::RepositoryDef::make_domain_schema(datastore::EntityName name) {
    Schema::DomainDef schema;
    schema.kv_segment(kDomainKVSegmentName)
        .compression_kind(seg::CompressionKind::kNone)
        .sub_dir_name(kDomainKVSegmentSubDirName)
        .tag(name2tag(name))
        .file_ext(kDomainKVSegmentFileExt);
    schema.existence_index(kDomainExistenceIndexName)
        .sub_dir_name(kDomainExistenceIndexSubDirName)
        .tag(name2tag(name))
        .file_ext(kDomainExistenceIndexFileExt);
    schema.btree_index(kDomainBTreeIndexName)
        .sub_dir_name(kDomainBTreeIndexSubDirName)
        .tag(name2tag(name))
        .file_ext(kDomainBTreeIndexFileExt);
    define_history_schema(name, schema);
    return schema;
}

Schema::DomainDef& Schema::DomainDef::with_accessor_index() {
    accessor_index(kDomainAccessorIndexName)
        .sub_dir_name(kDomainAccessorIndexSubDirName)
        .tag(kv_segment(kDomainKVSegmentName).tag())
        .file_ext(kDomainAccessorIndexFileExt);
    return *this;
}

Schema::EntityDef Schema::RepositoryDef::make_history_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_history_schema(name, schema);
    return schema;
}

void Schema::RepositoryDef::define_history_schema(datastore::EntityName name, EntityDef& schema) {
    schema.segment(kHistorySegmentName)
        .compression_enabled(false)
        .sub_dir_name(kHistorySegmentSubDirName)
        .tag(name2tag(name))
        .file_ext(kHistorySegmentFileExt);
    schema.accessor_index(kHistoryAccessorIndexName)
        .sub_dir_name(kHistoryAccessorIndexSubDirName)
        .tag(name2tag(name))
        .file_ext(kHistoryAccessorIndexFileExt);
    define_inverted_index_schema(name, schema);
}

void Schema::RepositoryDef::undefine_history_schema(EntityDef& schema) {
    schema.undefine(kHistorySegmentName);
    schema.undefine(kHistoryAccessorIndexName);
    undefine_inverted_index_schema(schema);
}

Schema::EntityDef Schema::RepositoryDef::make_inverted_index_schema(datastore::EntityName name) {
    Schema::EntityDef schema;
    define_inverted_index_schema(name, schema);
    return schema;
}

void Schema::RepositoryDef::define_inverted_index_schema(datastore::EntityName name, EntityDef& schema) {
    schema.kv_segment(kInvIdxKVSegmentName)
        .compression_kind(seg::CompressionKind::kNone)
        .sub_dir_name(kInvIdxKVSegmentSubDirName)
        .tag(name2tag(name))
        .file_ext(kInvIdxKVSegmentFileExt);
    schema.accessor_index(kInvIdxAccessorIndexName)
        .sub_dir_name(kInvIdxAccessorIndexSubDirName)
        .tag(name2tag(name))
        .file_ext(kInvIdxAccessorIndexFileExt);
}

void Schema::RepositoryDef::undefine_inverted_index_schema(EntityDef& schema) {
    schema.undefine(kInvIdxKVSegmentName);
    schema.undefine(kInvIdxAccessorIndexName);
}

}  // namespace silkworm::snapshots
