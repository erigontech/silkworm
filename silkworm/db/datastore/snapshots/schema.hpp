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
#include "segment/seg/compression_kind.hpp"

namespace silkworm::snapshots {

class Schema {
  public:
    class SnapshotFileDef {
      public:
        enum class Format {
            kSegment,
            kKVSegment,
            kAccessorIndex,
            kExistenceIndex,
            kBTreeIndex,
        };

        explicit SnapshotFileDef(Format format) : format_{format} {}
        virtual ~SnapshotFileDef() = default;

        SnapshotFileDef& sub_dir_name(std::string_view name) {
            sub_dir_name_ = name;
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

        SnapshotPath make_path(const std::filesystem::path& dir_path, datastore::StepRange range) const;

        Format format() const { return format_; }
        const std::optional<std::string>& sub_dir_name() const { return sub_dir_name_; }
        const std::string& tag() const { return tag_.value(); }
        const std::string& file_ext() const { return file_ext_.value(); }

      private:
        Format format_;
        std::optional<std::string> sub_dir_name_;
        std::optional<std::string> tag_;
        std::optional<std::string> file_ext_;
    };

    class SegmentDef : public SnapshotFileDef {
      public:
        explicit SegmentDef() : SnapshotFileDef{SnapshotFileDef::Format::kSegment} {}
        ~SegmentDef() override = default;

        SegmentDef& compression_enabled(bool value) {
            compression_enabled_ = value;
            return *this;
        }

        bool compression_enabled() const { return compression_enabled_; }

      private:
        bool compression_enabled_{true};
    };

    class KVSegmentDef : public SnapshotFileDef {
      public:
        explicit KVSegmentDef() : SnapshotFileDef{SnapshotFileDef::Format::kKVSegment} {}
        ~KVSegmentDef() override = default;

        KVSegmentDef& compression_kind(seg::CompressionKind compression_kind) {
            compression_kind_ = compression_kind;
            return *this;
        }

        seg::CompressionKind compression_kind() const { return *compression_kind_; }

      private:
        std::optional<seg::CompressionKind> compression_kind_;
    };

    class EntityDef {
      public:
        virtual ~EntityDef() = default;

        SegmentDef& segment(datastore::EntityName name) {
            file_defs_.try_emplace(name, std::make_shared<SegmentDef>());
            return dynamic_cast<SegmentDef&>(*file_defs_.at(name));
        }

        KVSegmentDef& kv_segment(datastore::EntityName name) {
            file_defs_.try_emplace(name, std::make_shared<KVSegmentDef>());
            return dynamic_cast<KVSegmentDef&>(*file_defs_.at(name));
        }

        SnapshotFileDef& accessor_index(datastore::EntityName name) {
            file_defs_.try_emplace(name, std::make_shared<SnapshotFileDef>(SnapshotFileDef::Format::kAccessorIndex));
            return *file_defs_.at(name);
        }

        SnapshotFileDef& existence_index(datastore::EntityName name) {
            file_defs_.try_emplace(name, std::make_shared<SnapshotFileDef>(SnapshotFileDef::Format::kExistenceIndex));
            return *file_defs_.at(name);
        }

        SnapshotFileDef& btree_index(datastore::EntityName name) {
            file_defs_.try_emplace(name, std::make_shared<SnapshotFileDef>(SnapshotFileDef::Format::kBTreeIndex));
            return *file_defs_.at(name);
        }

        EntityDef& undefine(datastore::EntityName name) {
            file_defs_.erase(name);
            return *this;
        }

        EntityDef& tag_override(std::string_view tag);

        const std::map<datastore::EntityName, std::shared_ptr<SnapshotFileDef>>& files() const { return file_defs_; }
        std::vector<std::string> file_extensions() const;
        std::optional<datastore::EntityName> entity_name_by_path(const SnapshotPath& path) const;

      private:
        std::map<datastore::EntityName, std::shared_ptr<SnapshotFileDef>> file_defs_;
    };

    class DomainDef : public EntityDef {
      public:
        ~DomainDef() override = default;

        DomainDef& kv_segment_compression_kind(seg::CompressionKind compression_kind) {
            kv_segment(kDomainKVSegmentName).compression_kind(compression_kind);
            return *this;
        }

        DomainDef& history_compression_enabled(bool value) {
            segment(kHistorySegmentName).compression_enabled(value);
            return *this;
        }

        DomainDef& without_history() {
            RepositoryDef::undefine_history_schema(*this);
            return *this;
        }

        DomainDef& with_accessor_index();
    };

    class RepositoryDef {
      public:
        EntityDef& default_entity() {
            entity_defs_.try_emplace(kDefaultEntityName, std::make_shared<EntityDef>());
            return *entity_defs_.at(kDefaultEntityName);
        }

        DomainDef& domain(datastore::EntityName name) {
            entity_defs_.try_emplace(name, std::make_shared<DomainDef>(make_domain_schema(name)));
            return dynamic_cast<DomainDef&>(*entity_defs_.at(name));
        }

        EntityDef& inverted_index(datastore::EntityName name) {
            entity_defs_.try_emplace(name, std::make_shared<EntityDef>(make_inverted_index_schema(name)));
            return *entity_defs_.at(name);
        }

        const std::map<datastore::EntityName, std::shared_ptr<EntityDef>>& entities() const { return entity_defs_; }
        std::vector<std::string> file_extensions() const;
        std::optional<std::pair<datastore::EntityName, datastore::EntityName>> entity_name_by_path(const SnapshotPath& path) const;

      private:
        friend DomainDef;
        static DomainDef make_domain_schema(datastore::EntityName name);
        static EntityDef make_history_schema(datastore::EntityName name);
        static void define_history_schema(datastore::EntityName name, EntityDef& schema);
        static void undefine_history_schema(EntityDef& schema);
        static EntityDef make_inverted_index_schema(datastore::EntityName name);
        static void define_inverted_index_schema(datastore::EntityName name, EntityDef& schema);
        static void undefine_inverted_index_schema(EntityDef& schema);

        std::map<datastore::EntityName, std::shared_ptr<EntityDef>> entity_defs_;
    };

    RepositoryDef& repository(datastore::EntityName name) {
        return repository_defs_[name];
    }

    static constexpr datastore::EntityName kDefaultEntityName{"_"};

    static constexpr datastore::EntityName kDomainKVSegmentName{"DomainKVSegment"};
    static constexpr std::string_view kDomainKVSegmentSubDirName{"domain"};
    static constexpr std::string_view kDomainKVSegmentFileExt{".kv"};
    static constexpr datastore::EntityName kDomainAccessorIndexName{"DomainAccessorIndex"};
    static constexpr std::string_view kDomainAccessorIndexSubDirName{"domain"};
    static constexpr std::string_view kDomainAccessorIndexFileExt{".kvi"};
    static constexpr datastore::EntityName kDomainExistenceIndexName{"DomainExistenceIndex"};
    static constexpr std::string_view kDomainExistenceIndexSubDirName{"domain"};
    static constexpr std::string_view kDomainExistenceIndexFileExt{".kvei"};
    static constexpr datastore::EntityName kDomainBTreeIndexName{"DomainBTreeIndex"};
    static constexpr std::string_view kDomainBTreeIndexSubDirName{"domain"};
    static constexpr std::string_view kDomainBTreeIndexFileExt{".bt"};

    static constexpr datastore::EntityName kHistorySegmentName{"HistorySegment"};
    static constexpr std::string_view kHistorySegmentSubDirName{"history"};
    static constexpr std::string_view kHistorySegmentFileExt{".v"};
    static constexpr datastore::EntityName kHistoryAccessorIndexName{"HistoryAccessorIndex"};
    static constexpr std::string_view kHistoryAccessorIndexSubDirName{"accessor"};
    static constexpr std::string_view kHistoryAccessorIndexFileExt{".vi"};

    static constexpr datastore::EntityName kInvIdxKVSegmentName{"InvIdxKVSegment"};
    static constexpr std::string_view kInvIdxKVSegmentSubDirName{"idx"};
    static constexpr std::string_view kInvIdxKVSegmentFileExt{".ef"};
    static constexpr datastore::EntityName kInvIdxAccessorIndexName{"InvIdxAccessorIndex"};
    static constexpr std::string_view kInvIdxAccessorIndexSubDirName{"accessor"};
    static constexpr std::string_view kInvIdxAccessorIndexFileExt{".efi"};

  private:
    std::map<datastore::EntityName, RepositoryDef> repository_defs_;
};

}  // namespace silkworm::snapshots
