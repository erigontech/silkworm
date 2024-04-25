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

#include "repository.hpp"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <ranges>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/db/snapshots/body_index.hpp>
#include <silkworm/db/snapshots/body_snapshot.hpp>
#include <silkworm/db/snapshots/header_index.hpp>
#include <silkworm/db/snapshots/header_snapshot.hpp>
#include <silkworm/db/snapshots/index_builder.hpp>
#include <silkworm/db/snapshots/txn_index.hpp>
#include <silkworm/db/snapshots/txn_queries.hpp>
#include <silkworm/db/snapshots/txn_to_block_index.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

namespace fs = std::filesystem;

std::size_t SnapshotRepository::view_bundles(const SnapshotBundleWalker& walker) {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    std::size_t visited_views{0};
    bool walk_done{false};
    for (auto& entry : std::ranges::reverse_view(bundles_)) {
        const auto& bundle = entry.second;
        walk_done = walker(bundle);
        ++visited_views;
        if (walk_done) break;
    }
    return visited_views;
}

// NOLINTNEXTLINE(modernize-pass-by-value)
SnapshotRepository::SnapshotRepository(const SnapshotSettings& settings) : settings_(settings) {}

SnapshotRepository::~SnapshotRepository() {
    close();
}

void SnapshotRepository::add_snapshot_bundle(SnapshotBundle bundle) {
    bundle.reopen();
    bundles_.emplace(bundle.block_from(), std::move(bundle));
}

void SnapshotBundle::reopen() {
    for (auto& snapshot_ref : snapshots()) {
        snapshot_ref.get().reopen_segment();
        ensure(!snapshot_ref.get().empty(), [&]() {
            return "invalid empty snapshot " + snapshot_ref.get().fs_path().string();
        });
    }
    for (auto& index_ref : indexes()) {
        index_ref.get().reopen_index();
    }
}

void SnapshotBundle::close() {
    for (auto& index_ref : indexes()) {
        index_ref.get().close_index();
    }
    for (auto& snapshot_ref : snapshots()) {
        snapshot_ref.get().close();
    }
}

void SnapshotRepository::close() {
    SILK_TRACE << "Close snapshot repository folder: " << settings_.repository_dir.string();
    for (auto& entry : bundles_) {
        auto& bundle = entry.second;
        bundle.close();
    }
}

BlockNum SnapshotRepository::max_block_available() const {
    if (bundles_.empty())
        return 0;

    // a bundle with the max block range is last in the sorted bundles map
    auto& bundle = bundles_.rbegin()->second;
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

bool SnapshotRepository::for_each_header(const HeaderWalker& fn) {
    for (auto& entry : bundles_) {
        auto& bundle = entry.second;
        const Snapshot& header_snapshot = bundle.header_snapshot;
        SILK_TRACE << "for_each_header header_snapshot: " << header_snapshot.fs_path().string();

        HeaderSnapshotReader reader{header_snapshot};
        for (auto& header : reader) {
            const bool keep_going = fn(header);
            if (!keep_going) return false;
        }
    }
    return true;
}

bool SnapshotRepository::for_each_body(const BodyWalker& fn) {
    for (auto& entry : bundles_) {
        auto& bundle = entry.second;
        const Snapshot& body_snapshot = bundle.body_snapshot;
        SILK_TRACE << "for_each_body body_snapshot: " << body_snapshot.fs_path().string();

        BlockNum number = body_snapshot.block_from();
        BodySnapshotReader reader{body_snapshot};
        for (auto& body : reader) {
            const bool keep_going = fn(number, body);
            if (!keep_going) return false;
            number++;
        }
    }
    return true;
}

std::size_t SnapshotRepository::view_segments(SnapshotType type, const SnapshotWalker& walker) {
    return view_bundles([&](const SnapshotBundle& bundle) {
        return walker({bundle.snapshot(type), bundle.index(type)});
    });
}

std::size_t SnapshotRepository::view_header_segments(const SnapshotWalker& walker) {
    return view_segments(SnapshotType::headers, walker);
}

std::size_t SnapshotRepository::view_body_segments(const SnapshotWalker& walker) {
    return view_segments(SnapshotType::bodies, walker);
}

std::size_t SnapshotRepository::view_tx_segments(const SnapshotWalker& walker) {
    return view_segments(SnapshotType::transactions, walker);
}

std::optional<SnapshotRepository::SnapshotAndIndex> SnapshotRepository::find_segment(SnapshotType type, BlockNum number) const {
    auto bundle = find_bundle(number);
    if (bundle) {
        return SnapshotAndIndex{bundle->snapshot(type), bundle->index(type)};
    }
    return std::nullopt;
}

std::optional<SnapshotRepository::SnapshotAndIndex> SnapshotRepository::find_header_segment(BlockNum number) const {
    return find_segment(SnapshotType::headers, number);
}

std::optional<SnapshotRepository::SnapshotAndIndex> SnapshotRepository::find_body_segment(BlockNum number) const {
    return find_segment(SnapshotType::bodies, number);
}

std::optional<SnapshotRepository::SnapshotAndIndex> SnapshotRepository::find_tx_segment(BlockNum number) const {
    return find_segment(SnapshotType::transactions, number);
}

std::optional<BlockNum> SnapshotRepository::find_block_number(Hash txn_hash) const {
    for (const auto& entry : std::ranges::reverse_view(bundles_)) {
        const auto& bundle = entry.second;
        const auto& snapshot = bundle.txn_snapshot;

        const Index& idx_txn_hash = bundle.idx_txn_hash;
        const Index& idx_txn_hash_2_block = bundle.idx_txn_hash_2_block;
        auto block = TransactionBlockNumByTxnHashQuery{idx_txn_hash_2_block, TransactionFindByHashQuery{snapshot, idx_txn_hash}}.exec(txn_hash);
        if (block) {
            return block;
        }
    }
    return {};
}

std::vector<std::shared_ptr<IndexBuilder>> SnapshotRepository::missing_indexes() const {
    SnapshotPathList segment_files = get_segment_files();
    std::vector<std::shared_ptr<IndexBuilder>> missing_index_list;

    for (const auto& seg_file : segment_files) {
        switch (seg_file.type()) {
            case SnapshotType::headers: {
                if (!fs::exists(seg_file.index_file().path())) {
                    auto index = std::make_shared<IndexBuilder>(HeaderIndex::make(seg_file));
                    missing_index_list.push_back(index);
                }
                break;
            }
            case SnapshotType::bodies: {
                if (!fs::exists(seg_file.index_file().path())) {
                    auto index = std::make_shared<IndexBuilder>(BodyIndex::make(seg_file));
                    missing_index_list.push_back(index);
                }
                break;
            }
            case SnapshotType::transactions: {
                auto bodies_segment_path = TransactionIndex::bodies_segment_path(seg_file);
                bool has_bodies_segment = (std::find(segment_files.begin(), segment_files.end(), bodies_segment_path) != segment_files.end());

                if (!fs::exists(seg_file.index_file().path()) && has_bodies_segment) {
                    auto index = std::make_shared<IndexBuilder>(TransactionIndex::make(bodies_segment_path, seg_file));
                    missing_index_list.push_back(index);
                }

                if (!fs::exists(seg_file.index_file_for_type(SnapshotType::transactions_to_block).path()) && has_bodies_segment) {
                    auto index = std::make_shared<IndexBuilder>(TransactionToBlockIndex::make(bodies_segment_path, seg_file));
                    missing_index_list.push_back(index);
                }
                break;
            }
            default: {
                SILKWORM_ASSERT(false);
            }
        }
    }

    return missing_index_list;
}

void SnapshotRepository::reopen_folder() {
    SILK_INFO << "Reopen snapshot repository folder: " << settings_.repository_dir.string();
    SnapshotPathList all_snapshot_paths = get_segment_files();
    SnapshotPathList all_index_paths = get_idx_files();

    std::map<BlockNum, std::map<bool, std::map<SnapshotType, size_t>>> groups;

    for (size_t i = 0; i < all_snapshot_paths.size(); i++) {
        auto& path = all_snapshot_paths[i];
        auto& group = groups[path.block_from()][false];
        group[path.type()] = i;
    }

    for (size_t i = 0; i < all_index_paths.size(); i++) {
        auto& path = all_index_paths[i];
        auto& group = groups[path.block_from()][true];
        group[path.type()] = i;
    }

    BlockNum num = 0;
    if (!groups.empty()) {
        num = groups.begin()->first;
    }

    while (groups.contains(num) &&
           (groups[num][false].size() == SnapshotBundle::kSnapshotsCount) &&
           (groups[num][true].size() == SnapshotBundle::kIndexesCount)) {
        if (!bundles_.contains(num)) {
            auto snapshot_path = [&](SnapshotType type) {
                return all_snapshot_paths[groups[num][false][type]];
            };
            auto index_path = [&](SnapshotType type) {
                return all_index_paths[groups[num][true][type]];
            };

            SnapshotBundle bundle{
                .header_snapshot = Snapshot(snapshot_path(SnapshotType::headers)),
                .idx_header_hash = Index(index_path(SnapshotType::headers)),

                .body_snapshot = Snapshot(snapshot_path(SnapshotType::bodies)),
                .idx_body_number = Index(index_path(SnapshotType::bodies)),

                .txn_snapshot = Snapshot(snapshot_path(SnapshotType::transactions)),
                .idx_txn_hash = Index(index_path(SnapshotType::transactions)),
                .idx_txn_hash_2_block = Index(index_path(SnapshotType::transactions_to_block)),
            };

            bundle.reopen();

            bundles_.emplace(num, std::move(bundle));
        }

        auto& bundle = bundles_.at(num);

        if (num < bundle.block_to()) {
            num = bundle.block_to();
        } else {
            break;
        }
    }

    SILK_INFO << "Total reopened bundles: " << bundles_count()
              << " snapshots: " << total_snapshots_count()
              << " indexes: " << total_indexes_count();
}

const SnapshotBundle* SnapshotRepository::find_bundle(BlockNum number) const {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    for (const auto& entry : std::ranges::reverse_view(bundles_)) {
        const auto& bundle = entry.second;
        // We're looking for the segment containing the target block number in its block range
        if (((bundle.block_from() <= number) && (number < bundle.block_to())) ||
            ((bundle.block_from() == number) && (bundle.block_from() == bundle.block_to()))) {
            return &bundle;
        }
    }
    return nullptr;
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

}  // namespace silkworm::snapshots
