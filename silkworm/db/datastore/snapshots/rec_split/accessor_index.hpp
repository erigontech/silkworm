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

#include <cstdint>
#include <memory>
#include <optional>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/types/hash.hpp>

#include "../common/snapshot_path.hpp"
#include "rec_split.hpp"

namespace silkworm::snapshots::rec_split {

class AccessorIndex {
  public:
    explicit AccessorIndex(
        SnapshotPath path,
        std::optional<MemoryMappedRegion> region = std::nullopt)
        : path_{std::move(path)},
          index_{path_.path(), region} {
    }

    std::optional<size_t> lookup_by_data_id(uint64_t id) const {
        return index_.lookup_by_data_id(id);
    }

    std::optional<size_t> lookup_by_hash(const Hash& hash) const {
        return index_.lookup_by_key(hash);
    }

    std::optional<size_t> lookup_ordinal_by_hash(const Hash& hash) const {
        auto [result, found] = index_.lookup(hash);
        return found ? std::optional{result} : std::nullopt;
    }

    const SnapshotPath& path() const { return path_; }
    const std::filesystem::path& fs_path() const { return path_.path(); }

    MemoryMappedRegion memory_file_region() const {
        return index_.memory_file_region();
    }

    uint64_t base_data_id() const {
        return index_.base_data_id();
    }

  private:
    SnapshotPath path_;
    rec_split::RecSplitIndex index_;
};

}  // namespace silkworm::snapshots::rec_split
