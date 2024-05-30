/*
   Copyright 2022 The Silkworm Authors

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

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/snapshots/common/iterator/map_values_view.hpp>
#include <silkworm/db/snapshots/index_builder.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/settings.hpp>
#include <silkworm/db/snapshots/snapshot_and_index.hpp>
#include <silkworm/db/snapshots/snapshot_bundle.hpp>

namespace silkworm::snapshots {

struct IndexBuilder;

//! Read-only repository for all snapshot files.
//! @details Some simplifications are currently in place:
//! - it opens snapshots only on startup and they are immutable
//! - all snapshots of given blocks range must exist (to make such range available)
//! - gaps in blocks range are not allowed
//! - segments have [from:to) semantic
class SnapshotRepository {
  public:
    explicit SnapshotRepository(const SnapshotSettings& settings = {});
    ~SnapshotRepository();

    [[nodiscard]] const SnapshotSettings& settings() const { return settings_; }
    [[nodiscard]] std::filesystem::path path() const { return settings_.repository_dir; }

    void reopen_folder();
    void close();

    void add_snapshot_bundle(SnapshotBundle bundle);

    [[nodiscard]] std::size_t bundles_count() const { return bundles_.size(); }
    [[nodiscard]] std::size_t total_snapshots_count() const { return bundles_count() * SnapshotBundle::kSnapshotsCount; }
    [[nodiscard]] std::size_t total_indexes_count() const { return bundles_count() * SnapshotBundle::kIndexesCount; }

    //! All types of .seg and .idx files are available up to this block number
    [[nodiscard]] BlockNum max_block_available() const;

    [[nodiscard]] std::vector<BlockNumRange> missing_block_ranges() const;

    [[nodiscard]] std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;
    void remove_stale_indexes() const;

    MapValuesView<BlockNum, SnapshotBundle> view_bundles() const { return MapValuesView{bundles_}; }
    auto view_bundles_reverse() const { return std::ranges::reverse_view(MapValuesView{bundles_}); }

    [[nodiscard]] std::optional<SnapshotAndIndex> find_segment(SnapshotType type, BlockNum number) const;

    [[nodiscard]] std::optional<BlockNum> find_block_number(Hash txn_hash) const;

  private:
    const SnapshotBundle* find_bundle(BlockNum number) const;

    [[nodiscard]] SnapshotPathList get_segment_files() const {
        return get_files(kSegmentExtension);
    }

    [[nodiscard]] SnapshotPathList get_idx_files() const {
        return get_files(kIdxExtension);
    }

    [[nodiscard]] SnapshotPathList get_files(const std::string& ext) const;

    SnapshotPathList stale_index_paths() const;

    //! The configuration settings for snapshots
    SnapshotSettings settings_;

    //! Full snapshot bundles ordered by block_from
    std::map<BlockNum, SnapshotBundle> bundles_;
};

}  // namespace silkworm::snapshots
