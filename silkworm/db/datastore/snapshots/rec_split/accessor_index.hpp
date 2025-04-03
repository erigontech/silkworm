// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    using RecSplitIndex::lookup_data_id_by_key;

    using RecSplitIndex::base_data_id;
    using RecSplitIndex::memory_file_region;

    const SnapshotPath& path() const { return path_; }
    const std::filesystem::path& fs_path() const { return path_.path(); }

  private:
    SnapshotPath path_;
};

}  // namespace silkworm::snapshots::rec_split
