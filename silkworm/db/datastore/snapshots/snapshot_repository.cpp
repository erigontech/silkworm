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

namespace silkworm::snapshots {

namespace fs = std::filesystem;

SnapshotRepository::SnapshotRepository(
    SnapshotSettings settings,
    std::unique_ptr<SnapshotBundleFactory> bundle_factory)
    : settings_(std::move(settings)),
      bundle_factory_(std::move(bundle_factory)),
      bundles_(std::make_shared<Bundles>()) {}

SnapshotRepository::~SnapshotRepository() {
    close();
}

void SnapshotRepository::add_snapshot_bundle(SnapshotBundle bundle) {
    replace_snapshot_bundles(std::move(bundle));
}

void SnapshotRepository::replace_snapshot_bundles(SnapshotBundle bundle) {
    bundle.reopen();

    std::scoped_lock lock(bundles_mutex_);
    // copy bundles prior to modification
    auto bundles = std::make_shared<Bundles>(*bundles_);

    std::erase_if(*bundles, [&](const auto& entry) {
        const SnapshotBundle& it = *entry.second;
        return (bundle.block_from() <= it.block_from()) && (it.block_to() <= bundle.block_to());
    });

    BlockNum block_from = bundle.block_from();
    bundles->insert_or_assign(block_from, std::make_shared<SnapshotBundle>(std::move(bundle)));

    bundles_ = bundles;
}

size_t SnapshotRepository::bundles_count() const {
    std::scoped_lock lock(bundles_mutex_);
    return bundles_->size();
}

void SnapshotRepository::close() {
    SILK_TRACE << "Close snapshot repository folder: " << settings_.repository_dir.string();
    std::scoped_lock lock(bundles_mutex_);
    bundles_ = std::make_shared<Bundles>();
}

BlockNum SnapshotRepository::max_block_available() const {
    std::scoped_lock lock(bundles_mutex_);
    if (bundles_->empty())
        return 0;

    // a bundle with the max block range is last in the sorted bundles map
    auto& bundle = *bundles_->rbegin()->second;
    return (bundle.block_from() < bundle.block_to()) ? bundle.block_to() - 1 : bundle.block_from();
}

std::vector<BlockNumRange> SnapshotRepository::missing_block_ranges() const {
    const auto ordered_segments = get_segment_files();

    std::vector<BlockNumRange> missing_ranges;
    BlockNum previous_to{0};
    for (const auto& segment : ordered_segments) {
        // skips different types of snapshots having the same block range
        if (segment.block_to() <= previous_to) continue;
        if (segment.block_from() != previous_to) {
            missing_ranges.emplace_back(previous_to, segment.block_from());
        }
        previous_to = segment.block_to();
    }
    return missing_ranges;
}

std::pair<std::optional<SnapshotAndIndex>, std::shared_ptr<SnapshotBundle>> SnapshotRepository::find_segment(SnapshotType type, BlockNum number) const {
    auto bundle = find_bundle(number);
    if (bundle) {
        return {bundle->snapshot_and_index(type), bundle};
    }
    return {std::nullopt, {}};
}

std::vector<std::shared_ptr<IndexBuilder>> SnapshotRepository::missing_indexes() const {
    SnapshotPathList segment_files = get_segment_files();
    auto index_builders = bundle_factory_->index_builders(segment_files);

    std::erase_if(index_builders, [&](const auto& builder) {
        return builder->path().exists();
    });
    return index_builders;
}

void SnapshotRepository::reopen_folder() {
    SILK_INFO << "Reopen snapshot repository folder: " << settings_.repository_dir.string();
    SnapshotPathList all_snapshot_paths = get_segment_files();
    SnapshotPathList all_index_paths = get_idx_files();

    std::map<BlockNum, std::map<bool, std::map<SnapshotType, size_t>>> groups;

    for (size_t i = 0; i < all_snapshot_paths.size(); ++i) {
        auto& path = all_snapshot_paths[i];
        auto& group = groups[path.block_from()][false];
        group[path.type()] = i;
    }

    for (size_t i = 0; i < all_index_paths.size(); ++i) {
        auto& path = all_index_paths[i];
        auto& group = groups[path.block_from()][true];
        group[path.type()] = i;
    }

    BlockNum num = 0;
    if (!groups.empty()) {
        num = groups.begin()->first;
    }

    std::unique_lock lock(bundles_mutex_);
    // copy bundles prior to modification
    auto bundles = std::make_shared<Bundles>(*bundles_);

    while (groups.contains(num) &&
           (groups[num][false].size() == SnapshotBundle::kSnapshotsCount) &&
           (groups[num][true].size() == SnapshotBundle::kIndexesCount)) {
        if (!bundles->contains(num)) {
            auto snapshot_path = [&](SnapshotType type) {
                return all_snapshot_paths[groups[num][false][type]];
            };
            auto index_path = [&](SnapshotType type) {
                return all_index_paths[groups[num][true][type]];
            };
            SnapshotBundle bundle = bundle_factory_->make(snapshot_path, index_path);
            bundle.reopen();

            bundles->insert_or_assign(num, std::make_shared<SnapshotBundle>(std::move(bundle)));
        }

        auto& bundle = *bundles->at(num);

        if (num < bundle.block_to()) {
            num = bundle.block_to();
        } else {
            break;
        }
    }

    bundles_ = bundles;
    lock.unlock();

    SILK_INFO << "Total reopened bundles: " << bundles_count()
              << " snapshots: " << total_snapshots_count()
              << " indexes: " << total_indexes_count()
              << " max block available: " << max_block_available();
}

std::shared_ptr<SnapshotBundle> SnapshotRepository::find_bundle(BlockNum number) const {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    for (const auto& bundle_ptr : this->view_bundles_reverse()) {
        auto& bundle = *bundle_ptr;
        // We're looking for the segment containing the target block number in its block range
        if (((bundle.block_from() <= number) && (number < bundle.block_to())) ||
            ((bundle.block_from() == number) && (bundle.block_from() == bundle.block_to()))) {
            return bundle_ptr;
        }
    }
    return {};
}

SnapshotPathList SnapshotRepository::get_files(const std::string& ext) const {
    ensure(fs::exists(settings_.repository_dir),
           [&]() { return "SnapshotRepository: " + settings_.repository_dir.string() + " does not exist"; });
    ensure(fs::is_directory(settings_.repository_dir),
           [&]() { return "SnapshotRepository: " + settings_.repository_dir.string() + " is a not folder"; });

    // Load the resulting files w/ desired extension ensuring they are snapshots
    SnapshotPathList snapshot_files;
    for (const auto& file : fs::directory_iterator{settings_.repository_dir}) {
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
    std::sort(snapshot_files.begin(), snapshot_files.end());

    return snapshot_files;
}

bool is_stale_index_path(const SnapshotPath& index_path) {
    SnapshotType snapshot_type = (index_path.type() == SnapshotType::transactions_to_block)
                                     ? SnapshotType::transactions
                                     : index_path.type();
    SnapshotPath snapshot_path = index_path.snapshot_path_for_type(snapshot_type);
    return (index_path.last_write_time() < snapshot_path.last_write_time());
}

SnapshotPathList SnapshotRepository::stale_index_paths() const {
    SnapshotPathList results;
    auto all_files = this->get_idx_files();
    std::copy_if(all_files.begin(), all_files.end(), std::back_inserter(results), is_stale_index_path);
    return results;
}

void SnapshotRepository::remove_stale_indexes() const {
    for (auto& path : stale_index_paths()) {
        const bool removed = fs::remove(path.path());
        ensure(removed, [&]() { return "SnapshotRepository::remove_stale_indexes: cannot remove index file " + path.path().string(); });
    }
}

void SnapshotRepository::build_indexes(SnapshotBundle& bundle) const {
    for (auto& builder : bundle_factory_->index_builders(bundle.snapshot_paths())) {
        builder->build();
    }
}

}  // namespace silkworm::snapshots
