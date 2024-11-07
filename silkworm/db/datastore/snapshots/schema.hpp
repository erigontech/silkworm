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
#include <variant>
#include <vector>

#include "../common/entity_name.hpp"
#include "common/snapshot_path.hpp"
#include "rec_split_index/index.hpp"
#include "segment/segment_reader.hpp"

namespace silkworm::snapshots {

class Schema {
  public:
    class RepositoryDef {
      public:
        RepositoryDef& segment(datastore::EntityName name) {
            segment_defs_.try_emplace(name);
            return *this;
        }

        RepositoryDef& rec_split_index(datastore::EntityName name) {
            rec_split_index_defs_.try_emplace(name);
            return *this;
        }

        std::map<datastore::EntityName, SnapshotPath> make_segment_paths(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, SegmentFileReader> make_segments(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, SnapshotPath> make_rec_split_index_paths(const std::filesystem::path& dir_path, StepRange range) const;
        std::map<datastore::EntityName, Index> make_rec_split_indexes(const std::filesystem::path& dir_path, StepRange range) const;
        std::vector<SnapshotPath> make_all_paths(const std::filesystem::path& dir_path, StepRange range) const;

      private:
        std::map<datastore::EntityName, std::monostate> segment_defs_;
        std::map<datastore::EntityName, std::monostate> rec_split_index_defs_;
    };

    RepositoryDef& repository(datastore::EntityName name) {
        return repository_defs_[name];
    }

  private:
    std::map<datastore::EntityName, RepositoryDef> repository_defs_;
};

}  // namespace silkworm::snapshots
