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
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "../common/entity_name.hpp"
#include "../common/step_timestamp_converter.hpp"
#include "common/snapshot_path.hpp"
#include "segment_and_accessor_index.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

struct IndexBuilder;
struct IndexBuildersFactory;

//! Read-only repository for all snapshot files.
//! @details Some simplifications are currently in place:
//! - all snapshots of given blocks range must exist (to make such range available)
//! - gaps in blocks range are not allowed
//! - segments have [from:to) semantic
class SnapshotRepository : public SnapshotRepositoryROAccess {
  public:
    using Timestamp = datastore::Timestamp;
    using Step = datastore::Step;
    using StepRange = datastore::StepRange;

    SnapshotRepository(
        datastore::EntityName name,
        std::filesystem::path dir_path,
        bool open,
        Schema::RepositoryDef schema,
        datastore::StepToTimestampConverter step_converter,
        std::optional<uint32_t> index_salt,
        std::unique_ptr<IndexBuildersFactory> index_builders_factory);

    SnapshotRepository(SnapshotRepository&&) = default;
    SnapshotRepository& operator=(SnapshotRepository&&) noexcept = delete;

    ~SnapshotRepository() override = default;

    const std::filesystem::path& path() const { return dir_path_; }
    const Schema::RepositoryDef& schema() const { return schema_; }
    const datastore::StepToTimestampConverter& step_converter() const { return step_converter_; }

    void reopen_folder();

    //! Opens a detached bundle of snapshot files. Use add_snapshot_bundle or replace_snapshot_bundles to add it.
    SnapshotBundle open_bundle(StepRange range) const;

    void add_snapshot_bundle(SnapshotBundle bundle);

    //! Replace bundles whose ranges are contained within the given bundle
    void replace_snapshot_bundles(SnapshotBundle bundle);

    size_t bundles_count() const override;

    Timestamp max_timestamp_available() const override;

    std::vector<std::shared_ptr<IndexBuilder>> missing_indexes() const;
    void remove_stale_indexes() const;
    const std::optional<uint32_t>& index_salt() const { return index_salt_; }
    void build_indexes(const SnapshotBundlePaths& bundle) const;

    BundlesView<MapValuesView<Bundles::key_type, Bundles::mapped_type, Bundles>> view_bundles() const override {
        std::scoped_lock lock(*bundles_mutex_);
        return BundlesView{make_map_values_view(*bundles_), bundles_};
    }
    BundlesView<MapValuesViewReverse<Bundles::key_type, Bundles::mapped_type, Bundles>> view_bundles_reverse() const override {
        std::scoped_lock lock(*bundles_mutex_);
        return BundlesView{std::ranges::reverse_view(make_map_values_view(*bundles_)), bundles_};
    }

    std::pair<std::optional<SegmentAndAccessorIndex>, std::shared_ptr<SnapshotBundle>> find_segment(
        const SegmentAndAccessorIndexNames& names,
        Timestamp t) const override;
    std::shared_ptr<SnapshotBundle> find_bundle(Timestamp t) const override;
    std::shared_ptr<SnapshotBundle> find_bundle(Step step) const override;

    std::vector<std::shared_ptr<SnapshotBundle>> bundles_in_range(StepRange range) const override;
    std::vector<std::shared_ptr<SnapshotBundle>> bundles_intersecting_range(StepRange range, bool ascending) const override;
    std::vector<std::shared_ptr<SnapshotBundle>> bundles_intersecting_range(TimestampRange range, bool ascending) const override;

  private:
    Step max_end_step() const;

    SnapshotPathList get_files(std::string_view ext) const;

    struct StepRangeCompare {
        inline bool operator()(const StepRange& lhs, const StepRange& rhs) const;
    };
    using StepRangeSet = std::set<StepRange, StepRangeCompare>;
    StepRangeSet list_dir_file_ranges() const;

    bool is_stale_index_path(const SnapshotPath& index_path) const;
    SnapshotPathList stale_index_paths() const;
    std::optional<uint32_t> load_index_salt() const;

    //! The repository entity name
    datastore::EntityName name_;

    //! Path to the snapshots directory
    std::filesystem::path dir_path_;

    //! Schema
    Schema::RepositoryDef schema_;

    //! Converts timestamp units to steps
    datastore::StepToTimestampConverter step_converter_;

    //! Index salt
    std::optional<uint32_t> index_salt_;

    //! Creates index builders
    std::unique_ptr<IndexBuildersFactory> index_builders_factory_;

    //! Full snapshot bundles ordered by block_from
    std::shared_ptr<Bundles> bundles_;
    std::unique_ptr<std::mutex> bundles_mutex_;
};

}  // namespace silkworm::snapshots
