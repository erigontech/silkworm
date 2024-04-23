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

#include <cassert>
#include <cstdint>
#include <memory>
#include <optional>

#include <silkworm/core/types/hash.hpp>

#include "path.hpp"
#include "rec_split/rec_split.hpp"

namespace silkworm::snapshots {

class Index {
  public:
    explicit Index(
        SnapshotPath path,
        std::optional<MemoryMappedRegion> region = std::nullopt)
        : path_(std::move(path)),
          region_(region) {}

    std::size_t lookup_by_data_id(uint64_t id) const { return index_->lookup_by_data_id(id); };
    std::optional<std::size_t> lookup_by_hash(const Hash& hash) const { return index_->lookup_by_key(hash); };

    std::optional<std::size_t> lookup_ordinal_by_hash(const Hash& hash) const {
        auto [result, found] = index_->lookup(hash);
        return found ? std::optional{result} : std::nullopt;
    }

    void reopen_index();
    void close_index();

    bool is_open() const { return index_.get(); }
    const SnapshotPath& path() const { return path_; }

    MemoryMappedRegion memory_file_region() const {
        return index_ ? index_->memory_file_region() : MemoryMappedRegion{};
    }

    uint64_t base_data_id() const {
        assert(index_);
        return index_->base_data_id();
    }

  private:
    SnapshotPath path_;
    //! External memory-mapped region of the index data
    std::optional<MemoryMappedRegion> region_;

    std::unique_ptr<rec_split::RecSplitIndex> index_;
};

}  // namespace silkworm::snapshots
