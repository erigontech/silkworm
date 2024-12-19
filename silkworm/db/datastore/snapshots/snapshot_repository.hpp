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

#include "../common/entity_name.hpp"
#include "common/snapshot_path.hpp"
#include "common/util/iterator/map_values_view.hpp"
#include "index_builder.hpp"
#include "index_builders_factory.hpp"
#include "segment_and_accessor_index.hpp"
#include "snapshot_bundle.hpp"

namespace silkworm::snapshots {

struct IndexBuilder;

//! Read-only repository for all snapshot files.
//! @details Some simplifications are currently in place:
//! - all snapshots of given blocks range must exist (to make such range available)
//! - gaps in blocks range are not allowed
//! - segments have [from:to) semantic
class SnapshotRepository {
  public:
    using Timestamp = datastore::Timestamp;
    using Step = datastore::Step;
    using StepRange = datastore::StepRange;

    SnapshotRepository(
        std::filesystem::path dir_path,
        bool open,
        Schema::RepositoryDef schema,
        std::unique_ptr<datastore::StepToTimestampConverter> step_converter,
        std::unique_ptr<IndexBuildersFactory> index_builders_factory);

    SnapshotRepository(SnapshotRepository&&) = default;
    SnapshotRepository& operator=(SnapshotRepository&&) noexcept = default;

    const std::filesystem::path& path() const { return dir_path_; }
    const Schema::RepositoryDef& schema() const { return schema_; };

    void reopen_folder();

    void add_snapshot_bundle(SnapshotBundle bundle);

    //! Replace bundles whose ranges are contained within the given bundle
    void replace_snapshot_bundles(SnapshotBundle bundle);

    size_t bundles_count() const;

    //! All types of .seg and .idx files are available up to this block number
    BlockNum max_block_available() const;
    Timestamp max_timestamp_available() const;

    std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;
    void remove_stale_indexes() const;
    void build_indexes(const SnapshotBundlePaths& bundle) const;

    using Bundles = std::map<Step, std::shared_ptr<SnapshotBundle>>;

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
        std::scoped_lock lock(*bundles_mutex_);
        return BundlesView{make_map_values_view(*bundles_), bundles_};
    }

    auto view_bundles_reverse() const {
        std::scoped_lock lock(*bundles_mutex_);
        return BundlesView{std::ranges::reverse_view(make_map_values_view(*bundles_)), bundles_};
    }

    std::pair<std::optional<SegmentAndAccessorIndex>, std::shared_ptr<SnapshotBundle>> find_segment(
        std::array<datastore::EntityName, 3> names,
        Timestamp t) const;
    std::shared_ptr<SnapshotBundle> find_bundle(Step step) const;

    std::vector<std::shared_ptr<SnapshotBundle>> bundles_in_range(StepRange range) const;

  private:
    Step max_end_step() const;

    SnapshotPathList get_files(std::string_view ext) const;
    std::vector<StepRange> list_dir_file_ranges() const;

    bool is_stale_index_path(const SnapshotPath& index_path) const;
    SnapshotPathList stale_index_paths() const;

    //! Path to the snapshots directory
    std::filesystem::path dir_path_;

    //! Schema
    Schema::RepositoryDef schema_;

    //! Converts timestamp units to steps
    std::unique_ptr<datastore::StepToTimestampConverter> step_converter_;

    //! Creates index builders
    std::unique_ptr<IndexBuildersFactory> index_builders_factory_;

    //! Full snapshot bundles ordered by block_from
    std::shared_ptr<Bundles> bundles_;
    std::unique_ptr<std::mutex> bundles_mutex_;
};

}  // namespace silkworm::snapshots
