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

#include <optional>

#include "../common/snapshot_path.hpp"
#include "rec_split.hpp"

namespace silkworm::snapshots::rec_split {

class AccessorIndex : private RecSplitIndex {
  public:
    explicit AccessorIndex(
        SnapshotPath path,
        std::optional<MemoryMappedRegion> region = std::nullopt)
        : RecSplitIndex{path.path(), region},
          path_{std::move(path)} {
    }

    using RecSplitIndex::lookup_by_data_id;
    using RecSplitIndex::lookup_by_key;

    using RecSplitIndex::base_data_id;
    using RecSplitIndex::memory_file_region;

    const SnapshotPath& path() const { return path_; }
    const std::filesystem::path& fs_path() const { return path_.path(); }

  private:
    SnapshotPath path_;
};

}  // namespace silkworm::snapshots::rec_split
