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

#include <map>
#include <optional>
#include <vector>

#include "../common/entity_name.hpp"
#include "common/snapshot_path.hpp"

namespace silkworm::snapshots {

class Schema {
  public:
    class SnapshotFileDef {
      public:
        enum class Format {
            kSegment,
            kKVSegment,
            kRecSplitIndex,
        };

        SnapshotFileDef& format(Format format) {
            format_ = format;
            return *this;
        }

        SnapshotFileDef& tag(std::string_view tag) {
            tag_ = tag;
            return *this;
        }

        SnapshotFileDef& file_ext(std::string_view ext) {
            file_ext_ = ext;
            return *this;
        }

        SnapshotPath make_path(const std::filesystem::path& dir_path, StepRange range) const;

        Format format() const { return format_.value(); }
        const std::string& tag() const { return tag_.value(); }
        const std::string& file_ext() const { return file_ext_.value(); }

      private:
        std::optional<Format> format_;
        std::optional<std::string> tag_;
        std::optional<std::string> file_ext_;
    };

    class EntityDef {
      public:
        SnapshotFileDef& segment(datastore::EntityName name) {
            return file_defs_[name].format(SnapshotFileDef::Format::kSegment);
        }

        SnapshotFileDef& kv_segment(datastore::EntityName name) {
            return file_defs_[name].format(SnapshotFileDef::Format::kKVSegment);
        }

        SnapshotFileDef& rec_split_index(datastore::EntityName name) {
            return file_defs_[name].format(SnapshotFileDef::Format::kRecSplitIndex);
        }

        EntityDef& tag_override(std::string_view tag);

        const std::map<datastore::EntityName, SnapshotFileDef>& entities() const { return file_defs_; }
        std::vector<std::string> file_extensions() const;
        std::optional<datastore::EntityName> entity_name_by_path(const SnapshotPath& path) const;

      private:
        std::map<datastore::EntityName, SnapshotFileDef> file_defs_;
    };

    class RepositoryDef {
      public:
        EntityDef& default_entity() {
            return entity_defs_[kDefaultEntityName];
        }

        EntityDef& domain(datastore::EntityName name) {
            entity_defs_.try_emplace(name, make_domain_schema(name));
            return entity_defs_.at(name);
        }

        EntityDef& inverted_index(datastore::EntityName name) {
            entity_defs_.try_emplace(name, make_inverted_index_schema(name));
            return entity_defs_.at(name);
        }

        const std::map<datastore::EntityName, EntityDef>& entities() const { return entity_defs_; }
        std::vector<std::string> file_extensions() const;
        std::optional<std::pair<datastore::EntityName, datastore::EntityName>> entity_name_by_path(const SnapshotPath& path) const;

      private:
        static EntityDef make_domain_schema(datastore::EntityName name);
        static EntityDef make_history_schema(datastore::EntityName name);
        static void define_history_schema(datastore::EntityName name, EntityDef& schema);
        static EntityDef make_inverted_index_schema(datastore::EntityName name);
        static void define_inverted_index_schema(datastore::EntityName name, EntityDef& schema);

        std::map<datastore::EntityName, EntityDef> entity_defs_;
    };

    RepositoryDef& repository(datastore::EntityName name) {
        return repository_defs_[name];
    }

    static constexpr datastore::EntityName kDefaultEntityName{"_"};

    static constexpr datastore::EntityName kDomainKVSegmentName{"DomainKVSegment"};
    static constexpr std::string_view kDomainKVSegmentFileExt{".kv"};
    static constexpr datastore::EntityName kDomainAccessorIndexName{"DomainAccessorIndex"};
    static constexpr std::string_view kDomainAccessorIndexFileExt{".kvi"};
    static constexpr datastore::EntityName kDomainExistenceIndexName{"DomainExistenceIndex"};
    static constexpr std::string_view kDomainExistenceIndexFileExt{".kvei"};
    static constexpr datastore::EntityName kDomainBTreeIndexName{"DomainBTreeIndex"};
    static constexpr std::string_view kDomainBTreeIndexFileExt{".bt"};

    static constexpr datastore::EntityName kHistorySegmentName{"HistorySegment"};
    static constexpr std::string_view kHistorySegmentFileExt{".v"};
    static constexpr datastore::EntityName kHistoryAccessorIndexName{"HistoryAccessorIndex"};
    static constexpr std::string_view kHistoryAccessorIndexFileExt{".vi"};

    static constexpr datastore::EntityName kInvIdxKVSegmentName{"InvIdxKVSegment"};
    static constexpr std::string_view kInvIdxKVSegmentFileExt{".ef"};
    static constexpr datastore::EntityName kInvIdxAccessorIndexName{"InvIdxAccessorIndex"};
    static constexpr std::string_view kInvIdxAccessorIndexFileExt{".efi"};

  private:
    std::map<datastore::EntityName, RepositoryDef> repository_defs_;
};

}  // namespace silkworm::snapshots
