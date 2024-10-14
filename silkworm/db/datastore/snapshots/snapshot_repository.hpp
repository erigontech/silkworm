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
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include <silkworm/core/common/base.hpp>

#include "common/iterator/map_values_view.hpp"
#include "index_builder.hpp"
#include "snapshot_and_index.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_bundle_factory.hpp"
#include "snapshot_path.hpp"
#include "snapshot_settings.hpp"

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
    explicit SnapshotRepository(
        SnapshotSettings settings,
        std::unique_ptr<SnapshotBundleFactory> bundle_factory);
    ~SnapshotRepository();

    [[nodiscard]] const SnapshotSettings& settings() const { return settings_; }
    [[nodiscard]] std::filesystem::path path() const { return settings_.repository_dir; }
    [[nodiscard]] const SnapshotBundleFactory& bundle_factory() const { return *bundle_factory_; }

    void reopen_folder();
    void close();

    void add_snapshot_bundle(SnapshotBundle bundle);

    //! Replace bundles whose ranges are contained within the given bundle
    void replace_snapshot_bundles(SnapshotBundle bundle);

    [[nodiscard]] size_t bundles_count() const;
    [[nodiscard]] size_t total_snapshots_count() const { return bundles_count() * SnapshotBundle::kSnapshotsCount; }
    [[nodiscard]] size_t total_indexes_count() const { return bundles_count() * SnapshotBundle::kIndexesCount; }

    //! All types of .seg and .idx files are available up to this block number
    [[nodiscard]] BlockNum max_block_available() const;

    [[nodiscard]] std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;
    void remove_stale_indexes() const;
    void build_indexes(SnapshotBundle& bundle) const;

    using Bundles = std::map<BlockNum, std::shared_ptr<SnapshotBundle>>;

    template <class TBaseView>
    class BundlesView : public std::ranges::view_interface<BundlesView<TBaseView>> {
      public:
        BundlesView(
            TBaseView base_view,
            std::shared_ptr<Bundles> bundles)
            : base_view_(std::move(base_view)),
              bundles_(std::move(bundles)) {}

        auto begin() const { return base_view_.begin(); }
        auto end() const { return base_view_.end(); }

      private:
        TBaseView base_view_;
        std::shared_ptr<Bundles> bundles_{};
    };

    auto view_bundles() const {
        std::scoped_lock lock(bundles_mutex_);
        return BundlesView{make_map_values_view(*bundles_), bundles_};
    }

    auto view_bundles_reverse() const {
        std::scoped_lock lock(bundles_mutex_);
        return BundlesView{std::ranges::reverse_view(make_map_values_view(*bundles_)), bundles_};
    }

    [[nodiscard]] std::pair<std::optional<SnapshotAndIndex>, std::shared_ptr<SnapshotBundle>> find_segment(SnapshotType type, BlockNum number) const;
    std::shared_ptr<SnapshotBundle> find_bundle(BlockNum number) const;

  private:
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

    //! SnapshotBundle factory
    std::unique_ptr<SnapshotBundleFactory> bundle_factory_;

    //! Full snapshot bundles ordered by block_from
    std::shared_ptr<Bundles> bundles_;
    mutable std::mutex bundles_mutex_;
};

}  // namespace silkworm::snapshots
