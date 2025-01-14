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

#include "snapshot_repository.hpp"

#include <algorithm>
#include <iterator>
#include <utility>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "index_builders_factory.hpp"

namespace silkworm::snapshots {

namespace fs = std::filesystem;
using namespace datastore;

SnapshotRepository::SnapshotRepository(
    std::filesystem::path dir_path,
    bool open,
    Schema::RepositoryDef schema,
    std::unique_ptr<StepToTimestampConverter> step_converter,
    std::unique_ptr<IndexBuildersFactory> index_builders_factory)
    : dir_path_(std::move(dir_path)),
      schema_(std::move(schema)),
      step_converter_(std::move(step_converter)),
      index_builders_factory_(std::move(index_builders_factory)),
      bundles_(std::make_shared<Bundles>()),
      bundles_mutex_(std::make_unique<std::mutex>()) {
    if (open) reopen_folder();
}

void SnapshotRepository::add_snapshot_bundle(SnapshotBundle bundle) {
    replace_snapshot_bundles(std::move(bundle));
}

void SnapshotRepository::replace_snapshot_bundles(SnapshotBundle bundle) {
    std::scoped_lock lock(*bundles_mutex_);
    // copy bundles prior to modification
    auto bundles = std::make_shared<Bundles>(*bundles_);

    std::erase_if(*bundles, [&](const auto& entry) {
        const SnapshotBundle& it = *entry.second;
        return bundle.step_range().contains_range(it.step_range());
    });

    Step key = bundle.step_range().start;
    bundles->insert_or_assign(key, std::make_shared<SnapshotBundle>(std::move(bundle)));

    bundles_ = bundles;
}

size_t SnapshotRepository::bundles_count() const {
    std::scoped_lock lock(*bundles_mutex_);
    return bundles_->size();
}

BlockNum SnapshotRepository::max_block_available() const {
    Step end_step = max_end_step();
    if (end_step.value == 0) return 0;
    return end_step.to_block_num() - 1;
}

Timestamp SnapshotRepository::max_timestamp_available() const {
    Step end_step = max_end_step();
    if (end_step.value == 0) return 0;
    return step_converter_->timestamp_from_step(end_step) - 1;
}

Step SnapshotRepository::max_end_step() const {
    std::scoped_lock lock(*bundles_mutex_);
    if (bundles_->empty())
        return Step{0};

    // a bundle with the max block range is last in the sorted bundles map
    auto& bundle = *bundles_->rbegin()->second;
    return bundle.step_range().end;
}

std::pair<std::optional<SegmentAndAccessorIndex>, std::shared_ptr<SnapshotBundle>> SnapshotRepository::find_segment(
    const SegmentAndAccessorIndexNames& names,
    Timestamp t) const {
    auto bundle = find_bundle(t);
    if (bundle) {
        return {bundle->segment_and_accessor_index(names), bundle};
    }
    return {std::nullopt, {}};
}

std::vector<std::shared_ptr<IndexBuilder>> SnapshotRepository::missing_indexes() const {
    // TODO: reimplement for state repository
    SnapshotBundlePaths some_bundle_paths{schema_, path(), {Step{0}, Step{1}}};
    auto segment_file_ext = some_bundle_paths.segment_paths().begin()->second.extension();
    SnapshotPathList segment_files = get_files(segment_file_ext);
    auto index_builders = index_builders_factory_->index_builders(segment_files);

    std::erase_if(index_builders, [&](const auto& builder) {
        return builder->path().exists();
    });
    return index_builders;
}

void SnapshotRepository::reopen_folder() {
    SILK_INFO << "Reopen snapshot repository folder: " << dir_path_.string();

    auto file_ranges = list_dir_file_ranges();
    if (file_ranges.empty()) return;

    // sort file_ranges by range.start
    std::ranges::sort(file_ranges, [](const StepRange& r1, const StepRange& r2) -> bool {
        return r1.start < r2.start;
    });

    std::unique_lock lock(*bundles_mutex_);
    // copy bundles prior to modification
    auto bundles = std::make_shared<Bundles>(*bundles_);

    Step num = file_ranges[0].start;
    for (const auto& range : file_ranges) {
        // avoid gaps/overlaps
        if (range.start != num) continue;
        if (range.size() == 0) continue;

        if (!bundles->contains(num)) {
            SnapshotBundlePaths bundle_paths{schema_, dir_path_, range};
            // if all bundle paths exist
            if (std::ranges::all_of(bundle_paths.files(), [](const fs::path& p) { return fs::exists(p); })) {
                SnapshotBundle bundle{schema_, dir_path_, range};
                bundles->insert_or_assign(num, std::make_shared<SnapshotBundle>(std::move(bundle)));
            }
        }

        // avoid gaps/overlaps
        num = range.end;
    }

    bundles_ = bundles;
    lock.unlock();

    SILK_INFO << "Total reopened bundles: " << bundles_count()
              << " max block available: " << max_block_available();
}

std::shared_ptr<SnapshotBundle> SnapshotRepository::find_bundle(Timestamp t) const {
    return find_bundle(step_converter_->step_from_timestamp(t));
}

std::shared_ptr<SnapshotBundle> SnapshotRepository::find_bundle(Step step) const {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    for (const auto& bundle_ptr : this->view_bundles_reverse()) {
        auto& bundle = *bundle_ptr;
        if (bundle.step_range().contains(step) ||
            ((bundle.step_range().start == step) && (bundle.step_range().size() == 0))) {
            return bundle_ptr;
        }
    }
    return {};
}

std::vector<std::shared_ptr<SnapshotBundle>> SnapshotRepository::bundles_in_range(StepRange range) const {
    std::vector<std::shared_ptr<SnapshotBundle>> bundles;
    for (const auto& bundle : view_bundles()) {
        if (range.contains_range(bundle->step_range())) {
            bundles.push_back(bundle);
        }
    }
    return bundles;
}

std::vector<std::shared_ptr<SnapshotBundle>> SnapshotRepository::bundles_intersecting_range(StepRange range, bool ascending) const {
    if (range.size() == 0) {
        return {};
    }
    std::vector<std::shared_ptr<SnapshotBundle>> bundles;
    for (const auto& bundle : view_bundles()) {
        StepRange bundle_range = bundle->step_range();
        if (range.contains_range(bundle_range) || bundle_range.contains(range.start) || bundle_range.contains(Step{range.end.value - 1})) {
            bundles.push_back(bundle);
        }
    }
    if (!ascending) {
        std::ranges::reverse(bundles);
    }
    return bundles;
}

std::vector<std::shared_ptr<SnapshotBundle>> SnapshotRepository::bundles_intersecting_range(TimestampRange range, bool ascending) const {
    if (range.size() == 0) {
        return {};
    }
    return bundles_intersecting_range(step_converter_->step_range_from_timestamp_range(range), ascending);
}

SnapshotPathList SnapshotRepository::get_files(std::string_view ext) const {
    ensure(fs::exists(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " does not exist"; });
    ensure(fs::is_directory(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " is a not folder"; });

    // Load the resulting files w/ desired extension ensuring they are snapshots
    SnapshotPathList snapshot_files;
    for (const auto& file : fs::directory_iterator{dir_path_}) {
        if (!fs::is_regular_file(file.path()) || file.path().extension().string() != ext) {
            continue;
        }
        SILK_TRACE << "Path: " << file.path() << " name: " << file.path().filename();
        const auto snapshot_file = SnapshotPath::parse(file);
        if (snapshot_file) {
            snapshot_files.push_back(snapshot_file.value());
        } else {
            SILK_TRACE << "unexpected format for file: " << file.path().filename() << ", skipped";
        }
    }

    // Order snapshot files by version/block-range/type
    std::ranges::sort(snapshot_files, std::less{});

    return snapshot_files;
}

std::vector<StepRange> SnapshotRepository::list_dir_file_ranges() const {
    ensure(fs::exists(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " does not exist"; });
    ensure(fs::is_directory(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " is a not folder"; });

    auto supported_file_extensions = schema_.file_extensions();
    if (supported_file_extensions.empty()) return {};

    std::vector<StepRange> results;
    for (const auto& file : fs::recursive_directory_iterator{dir_path_}) {
        if (!fs::is_regular_file(file.path())) {
            continue;
        }
        if (std::ranges::find(supported_file_extensions, file.path().extension().string()) == supported_file_extensions.end()) {
            continue;
        }
        const auto path = SnapshotPath::parse(file.path(), dir_path_);
        if (path) {
            results.push_back(path->step_range());
        }
    }

    return results;
}

bool SnapshotRepository::is_stale_index_path(const SnapshotPath& index_path) const {
    return std::ranges::any_of(
        index_builders_factory_->index_dependency_paths(index_path),
        [&](const SnapshotPath& dep_path) { return fs::last_write_time(index_path.path()) < fs::last_write_time(dep_path.path()); });
}

SnapshotPathList SnapshotRepository::stale_index_paths() const {
    SnapshotPathList results;
    // TODO: reimplement for state repository
    SnapshotBundlePaths some_bundle_paths{schema_, path(), {Step{0}, Step{1}}};
    auto accessor_index_file_ext = some_bundle_paths.accessor_index_paths().begin()->second.extension();
    auto all_files = get_files(accessor_index_file_ext);
    std::ranges::copy_if(
        all_files,
        std::back_inserter(results),
        [this](const SnapshotPath& index_path) { return this->is_stale_index_path(index_path); });
    return results;
}

void SnapshotRepository::remove_stale_indexes() const {
    for (auto& path : stale_index_paths()) {
        const bool removed = fs::remove(path.path());
        ensure(removed, [&]() { return "SnapshotRepository::remove_stale_indexes: cannot remove index file " + path.path().string(); });
    }
}

void SnapshotRepository::build_indexes(const SnapshotBundlePaths& bundle) const {
    std::vector<SnapshotPath> segment_paths;
    for (auto& entry : bundle.segment_paths())
        segment_paths.push_back(std::move(entry.second));

    for (auto& builder : index_builders_factory_->index_builders(segment_paths)) {
        builder->build();
    }
}

}  // namespace silkworm::snapshots
