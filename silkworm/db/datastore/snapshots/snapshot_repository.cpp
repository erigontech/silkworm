// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "snapshot_repository.hpp"

#include <algorithm>
#include <future>
#include <iterator>
#include <utility>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>

#include "index_builders_factory.hpp"
#include "index_salt_file.hpp"

namespace silkworm::snapshots {

namespace fs = std::filesystem;
using namespace datastore;

SnapshotRepository::SnapshotRepository(
    datastore::EntityName name,
    std::filesystem::path dir_path,
    bool open,
    Schema::RepositoryDef schema,
    StepToTimestampConverter step_converter,
    std::optional<uint32_t> index_salt,
    std::unique_ptr<IndexBuildersFactory> index_builders_factory,
    std::optional<DomainGetLatestCaches> domain_caches,
    std::optional<InvertedIndexSeekCaches> inverted_index_caches)
    : name_(std::move(name)),
      dir_path_(std::move(dir_path)),
      schema_(std::move(schema)),
      step_converter_(std::move(step_converter)),
      index_salt_(index_salt),
      index_builders_factory_(std::move(index_builders_factory)),
      bundles_(std::make_shared<Bundles>()),
      bundles_mutex_(std::make_unique<std::mutex>()),
      domain_caches_{std::move(domain_caches)},
      inverted_index_caches_{std::move(inverted_index_caches)} {
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

DomainGetLatestCache* SnapshotRepository::domain_get_latest_cache(const datastore::EntityName& name) const {
    if (!domain_caches_) return nullptr;
    if (!domain_caches_->contains(name)) return nullptr;
    return domain_caches_->at(name).get();
}

InvertedIndexSeekCache* SnapshotRepository::inverted_index_seek_cache(const datastore::EntityName& name) const {
    if (!inverted_index_caches_) return nullptr;
    if (!inverted_index_caches_->contains(name)) return nullptr;
    return inverted_index_caches_->at(name).get();
}

size_t SnapshotRepository::bundles_count() const {
    std::scoped_lock lock(*bundles_mutex_);
    return bundles_->size();
}

Timestamp SnapshotRepository::max_timestamp_available() const {
    Step end_step = max_end_step();
    if (end_step.value == 0) return 0;
    return step_converter_.timestamp_from_step(end_step) - 1;
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
    SILK_INFO << "Reopen " << name_.to_string() << " snapshot repository folder: " << dir_path_.string();

    index_salt_ = load_index_salt();

    auto file_ranges = list_dir_file_ranges();
    if (file_ranges.empty()) return;

    ThreadPool worker_pool;

    std::unique_lock lock(*bundles_mutex_);

    std::vector<std::future<std::shared_ptr<SnapshotBundle>>> future_complete_bundles;
    for (const auto& range : file_ranges) {
        if (range.size() == 0) continue;

        SnapshotBundlePaths bundle_paths{schema_, dir_path_, range};
        // Open iff all bundle paths exist
        if (std::ranges::all_of(bundle_paths.files(), [](const fs::path& p) { return fs::exists(p); })) {
            // Schedule each bundle opening on worker pool collecting its future result for completion handling
            future_complete_bundles.emplace_back(worker_pool.submit([&, range]() -> std::shared_ptr<SnapshotBundle> {
                return std::make_shared<SnapshotBundle>(schema_, dir_path_, range, index_salt_);
            }));
        }
    }
    for (auto& future_bundle_ptr : future_complete_bundles) {
        std::shared_ptr<SnapshotBundle> bundle_ptr = future_bundle_ptr.get();
        const auto step_range = bundle_ptr->step_range();
        bundles_->insert_or_assign(step_range.start, std::move(bundle_ptr));
    }

#ifndef NDEBUG
    // Sanity check: no gap must exist in bundles
    if (!bundles_->empty()) {
        Step max_end = bundles_->cbegin()->second->step_range().start;
        for (const auto& b : *bundles_) {
            SILKWORM_ASSERT(b.second->step_range().start == max_end);
            max_end = b.second->step_range().end;
        }
    }
#endif  // NDEBUG

    lock.unlock();

    SILK_INFO << "Total reopened " << name_.to_string() << " snapshot repository bundles: " << bundles_count()
              << " max available: " + std::to_string(max_timestamp_available());
}

SnapshotBundle SnapshotRepository::open_bundle(StepRange range) const {
    return SnapshotBundle{schema_, dir_path_, range, index_salt_};
}

std::shared_ptr<SnapshotBundle> SnapshotRepository::find_bundle(Timestamp t) const {
    return find_bundle(step_converter_.step_from_timestamp(t));
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
    return bundles_intersecting_range(step_converter_.step_range_from_timestamp_range(range), ascending);
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

// Define the datastore::StepRange ordering semantics necessary for SnapshotRepository::list_dir_file_ranges
bool SnapshotRepository::StepRangeCompare::operator()(const StepRange& lhs, const StepRange& rhs) const {
    if (lhs.start != rhs.start) {
        return lhs.start < rhs.start;
    }
    return lhs.size() < rhs.size();
}

SnapshotRepository::StepRangeSet SnapshotRepository::list_dir_file_ranges() const {
    ensure(fs::exists(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " does not exist"; });
    ensure(fs::is_directory(dir_path_),
           [&]() { return "SnapshotRepository: " + dir_path_.string() + " is a not folder"; });

    auto supported_file_extensions = schema_.file_extensions();
    if (supported_file_extensions.empty()) return {};

    StepRangeSet results;
    for (const auto& file : fs::recursive_directory_iterator{dir_path_}) {
        if (!fs::is_regular_file(file.path())) {
            continue;
        }
        if (std::ranges::find(supported_file_extensions, file.path().extension().string()) == supported_file_extensions.end()) {
            continue;
        }
        const auto path = SnapshotPath::parse(file.path(), dir_path_);
        if (path) {
            results.insert(path->step_range());
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

std::optional<uint32_t> SnapshotRepository::load_index_salt() const {
    IndexSaltFile file{this->dir_path_ / schema_.index_salt_file_name()};
    return file.exists() ? file.load() : std::optional<uint32_t>{};
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
