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
#include "kv_segment/kv_segment_reader.hpp"
#include "rec_split_index/index.hpp"
#include "segment/segment_reader.hpp"

namespace silkworm::snapshots {

class Schema {
  public:
    class SnapshotPathDef {
      public:
        SnapshotPathDef& file_ext(std::string_view ext) {
            file_ext_ = ext;
            return *this;
        }

        const std::string& file_ext() const { return file_ext_; }

      private:
        std::string file_ext_;
    };

    class EntityDef {
      public:
        SnapshotPathDef& segment(datastore::EntityName name) {
            return segment_defs_[name];
        }

        SnapshotPathDef& kv_segment(datastore::EntityName name) {
            return kv_segment_defs_[name];
        }

        SnapshotPathDef& rec_split_index(datastore::EntityName name) {
            return rec_split_index_defs_[name];
        }

        std::map<datastore::EntityName, SnapshotPath> make_segment_paths(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, SegmentFileReader> make_segments(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, SnapshotPath> make_kv_segment_paths(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, KVSegmentFileReader> make_kv_segments(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, SnapshotPath> make_rec_split_index_paths(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, Index> make_rec_split_indexes(const std::filesystem::path& dir_path, StepRange range) const;
        std::vector<SnapshotPath> make_all_paths(const std::filesystem::path& dir_path, StepRange range) const;

        std::vector<std::string> file_extensions() const;

      protected:
        std::map<datastore::EntityName, SnapshotPathDef> segment_defs_;
        std::map<datastore::EntityName, SnapshotPathDef> kv_segment_defs_;
        std::map<datastore::EntityName, SnapshotPathDef> rec_split_index_defs_;
    };

    class RepositoryDef {
      public:
        EntityDef& default_entity() {
            return entity_defs_[kDefaultEntityName];
        }

        void domain(datastore::EntityName name) {
            entity_defs_.try_emplace(name, make_domain_schema());
        }

        void inverted_index(datastore::EntityName name) {
            entity_defs_.try_emplace(name, make_inverted_index_schema());
        }

        const std::map<datastore::EntityName, EntityDef>& entities() const { return entity_defs_; }
        std::vector<std::string> file_extensions() const;

      private:
        static EntityDef make_domain_schema();
        static EntityDef make_history_schema();
        static void define_history_schema(EntityDef& schema);
        static EntityDef make_inverted_index_schema();
        static void define_inverted_index_schema(EntityDef& schema);

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
