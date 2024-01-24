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
#include <ranges>
#include <utility>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/snapshots/index.hpp>

namespace silkworm::snapshots {

namespace fs = std::filesystem;

template <ConcreteSnapshot T>
const T* get_segment(const SnapshotsByPath<T>& segments, const SnapshotPath& path) {
    if (not segments.contains(path.path())) {
        return nullptr;
    }
    return segments.find(path.path())->second.get();
}

template <ConcreteSnapshot T>
SnapshotRepository::ViewResult view(const SnapshotsByPath<T>& segments, BlockNum number, const SnapshotWalker<T>& walker) {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    for (auto it = segments.rbegin(); it != segments.rend(); ++it) {
        const auto& snapshot = it->second;
        // We're looking for the segment containing the target block number in its block range
        if (snapshot->block_from() <= number && number < snapshot->block_to()) {
            const bool walk_done = walker(snapshot.get());
            return walk_done ? SnapshotRepository::kWalkSuccess : SnapshotRepository::kWalkFailed;
        }
    }
    return SnapshotRepository::kSnapshotNotFound;
}

template <ConcreteSnapshot T>
std::size_t view(const SnapshotsByPath<T>& segments, const SnapshotWalker<T>& walker) {
    // Search for target segment in reverse order (from the newest segment to the oldest one)
    std::size_t visited_views{0};
    bool walk_done{false};
    for (auto it = segments.rbegin(); it != segments.rend() && !walk_done; ++it) {
        const auto& snapshot = it->second;
        walk_done = walker(snapshot.get());
        ++visited_views;
    }
    return visited_views;
}

// NOLINTNEXTLINE(modernize-pass-by-value)
SnapshotRepository::SnapshotRepository(const SnapshotSettings& settings) : settings_(settings) {}

SnapshotRepository::~SnapshotRepository() {
    close();
}

void SnapshotRepository::add_snapshot_bundle(SnapshotBundle&& bundle) {
    header_segments_[bundle.headers_snapshot_path.path()] = std::move(bundle.headers_snapshot);
    body_segments_[bundle.bodies_snapshot_path.path()] = std::move(bundle.bodies_snapshot);
    tx_segments_[bundle.tx_snapshot_path.path()] = std::move(bundle.tx_snapshot);
    if (bundle.tx_snapshot_path.block_to() > segment_max_block_) {
        segment_max_block_ = bundle.tx_snapshot_path.block_to() - 1;
    }
    idx_max_block_ = max_idx_available();
}

void SnapshotRepository::reopen_folder() {
    SILK_INFO << "Reopen snapshot repository folder: " << settings_.repository_dir.string();
    SnapshotPathList segment_files = get_segment_files();
    reopen_list(segment_files);
    SILK_INFO << "Total reopened snapshots: " << total_snapshots_count();
}

void SnapshotRepository::close() {
    SILK_TRACE << "Close snapshot repository folder: " << settings_.repository_dir.string();
    for (const auto& [_, header_seg] : this->header_segments_) {
        header_seg->close();
    }
    for (const auto& [_, body_seg] : this->body_segments_) {
        body_seg->close();
    }
    for (const auto& [_, tx_seg] : this->tx_segments_) {
        tx_seg->close();
    }
}

std::vector<BlockNumRange> SnapshotRepository::missing_block_ranges() const {
    const auto ordered_segments = get_segment_files();

    std::vector<BlockNumRange> missing_ranges;
    BlockNum previous_to{0};
    for (const auto& segment : ordered_segments) {
        if (segment.block_to() <= previous_to) continue;
        if (segment.block_from() != previous_to) {
            missing_ranges.emplace_back(previous_to, segment.block_from());
        }
        previous_to = segment.block_to();
    }
    return missing_ranges;
}

bool SnapshotRepository::for_each_header(const HeaderSnapshot::Walker& fn) {
    for (const auto& [_, header_snapshot] : header_segments_) {
        SILK_TRACE << "for_each_header header_snapshot: " << header_snapshot->fs_path().string();
        const auto keep_going = header_snapshot->for_each_header([fn](const auto* header) {
            return fn(header);
        });
        if (!keep_going) return false;
    }
    return true;
}

bool SnapshotRepository::for_each_body(const BodySnapshot::Walker& fn) {
    for (const auto& [_, body_snapshot] : body_segments_) {
        SILK_TRACE << "for_each_body body_snapshot: " << body_snapshot->fs_path().string();
        const auto keep_going = body_snapshot->for_each_body([fn](BlockNum number, const auto* body) {
            return fn(number, body);
        });
        if (!keep_going) return false;
    }
    return true;
}

SnapshotRepository::ViewResult SnapshotRepository::view_header_segment(BlockNum number, const HeaderSnapshotWalker& walker) {
    return view(header_segments_, number, walker);
}

SnapshotRepository::ViewResult SnapshotRepository::view_body_segment(BlockNum number, const BodySnapshotWalker& walker) {
    return view(body_segments_, number, walker);
}

SnapshotRepository::ViewResult SnapshotRepository::view_tx_segment(BlockNum number, const TransactionSnapshotWalker& walker) {
    return view(tx_segments_, number, walker);
}

std::size_t SnapshotRepository::view_header_segments(const HeaderSnapshotWalker& walker) {
    return view(header_segments_, walker);
}

std::size_t SnapshotRepository::view_body_segments(const BodySnapshotWalker& walker) {
    return view(body_segments_, walker);
}

std::size_t SnapshotRepository::view_tx_segments(const TransactionSnapshotWalker& walker) {
    return view(tx_segments_, walker);
}

const HeaderSnapshot* SnapshotRepository::get_header_segment(const SnapshotPath& path) const {
    return get_segment(header_segments_, path);
}

const BodySnapshot* SnapshotRepository::get_body_segment(const SnapshotPath& path) const {
    return get_segment(body_segments_, path);
}

const TransactionSnapshot* SnapshotRepository::get_tx_segment(const SnapshotPath& path) const {
    return get_segment(tx_segments_, path);
}

const HeaderSnapshot* SnapshotRepository::find_header_segment(BlockNum number) const {
    return find_segment(header_segments_, number);
}

const BodySnapshot* SnapshotRepository::find_body_segment(BlockNum number) const {
    return find_segment(body_segments_, number);
}

const TransactionSnapshot* SnapshotRepository::find_tx_segment(BlockNum number) const {
    return find_segment(tx_segments_, number);
}

std::optional<BlockNum> SnapshotRepository::find_block_number(Hash txn_hash) const {
    for (const auto& it : std::ranges::reverse_view(tx_segments_)) {
        const auto& snapshot = it.second;
        auto block = snapshot->block_num_by_txn_hash(txn_hash);
        if (block) {
            return block;
        }
    }
    return {};
}

std::vector<std::shared_ptr<Index>> SnapshotRepository::missing_indexes() const {
    SnapshotPathList segment_files = get_segment_files();
    std::vector<std::shared_ptr<Index>> missing_index_list;
    missing_index_list.reserve(segment_files.size());
    for (const auto& seg_file : segment_files) {
        const auto index_file = seg_file.index_file();
        SILK_INFO << "Segment file: " << seg_file.filename() << " has index: " << index_file.filename();
        if (!std::filesystem::exists(index_file.path())) {
            std::shared_ptr<Index> index;
            switch (seg_file.type()) {
                case SnapshotType::headers: {
                    index = std::make_shared<HeaderIndex>(seg_file);
                    break;
                }
                case SnapshotType::bodies: {
                    index = std::make_shared<BodyIndex>(seg_file);
                    break;
                }
                case SnapshotType::transactions: {
                    index = std::make_shared<TransactionIndex>(seg_file);
                    break;
                }
                default: {
                    SILKWORM_ASSERT(false);
                }
            }
            missing_index_list.push_back(index);
        }
    }
    return missing_index_list;
}

void SnapshotRepository::reopen_file(const SnapshotPath& segment_path, bool optimistic) {
    reopen_list(SnapshotPathList{segment_path}, optimistic);
}

void SnapshotRepository::reopen_list(const SnapshotPathList& segment_files, bool optimistic) {
    BlockNum segment_max_block{0};
    for (const auto& seg_file : segment_files) {
        try {
            SILK_TRACE << "Reopen segment file: " << seg_file.path().filename().string();
            bool snapshot_valid{true};
            switch (seg_file.type()) {
                case SnapshotType::headers: {
                    const auto header_it = header_segments_.find(seg_file.path());
                    if (header_it != header_segments_.end()) {
                        header_it->second->reopen_index();
                    } else {
                        snapshot_valid = reopen_header(seg_file);
                    }
                    break;
                }
                case SnapshotType::bodies: {
                    const auto body_it = body_segments_.find(seg_file.path());
                    if (body_it != body_segments_.end()) {
                        body_it->second->reopen_index();
                    } else {
                        snapshot_valid = reopen_body(seg_file);
                    }
                    break;
                }
                case SnapshotType::transactions: {
                    const auto tx_it = tx_segments_.find(seg_file.path());
                    if (tx_it != tx_segments_.end()) {
                        tx_it->second->reopen_index();
                    } else {
                        snapshot_valid = reopen_transaction(seg_file);
                    }
                    break;
                }
                default: {
                    SILKWORM_ASSERT(false);
                }
            }
            ensure(snapshot_valid, [&]() { return "invalid empty snapshot " + seg_file.filename(); });

            if (seg_file.block_to() > segment_max_block) {
                segment_max_block = seg_file.block_to() - 1;
            }
        } catch (const std::exception& exc) {
            SILK_WARN << "Reopen failed for: " << seg_file.path() << " [" << exc.what() << "]";
            if (!optimistic) throw;
        }
    }
    segment_max_block_ = segment_max_block;
    idx_max_block_ = max_idx_available();
}

bool SnapshotRepository::reopen_header(const SnapshotPath& seg_file) {
    return reopen(header_segments_, seg_file);
}

bool SnapshotRepository::reopen_body(const SnapshotPath& seg_file) {
    return reopen(body_segments_, seg_file);
}

bool SnapshotRepository::reopen_transaction(const SnapshotPath& seg_file) {
    return reopen(tx_segments_, seg_file);
}

template <ConcreteSnapshot T>
const T* SnapshotRepository::find_segment(const SnapshotsByPath<T>& segments, BlockNum number) const {
    if (number > max_block_available()) {
        return nullptr;
    }

    // Search for target segment in reverse order (from the newest segment to the oldest one)
    for (auto it = segments.rbegin(); it != segments.rend(); ++it) {
        const auto& snapshot = it->second;
        // We're looking for the segment containing the target block number in its block range
        if (snapshot->block_from() <= number && number < snapshot->block_to()) {
            return snapshot.get();
        }
    }
    return nullptr;
}

template <ConcreteSnapshot T>
bool SnapshotRepository::reopen(SnapshotsByPath<T>& segments, const SnapshotPath& seg_file) {
    if (segments.find(seg_file.path()) == segments.end()) {
        auto segment = std::make_unique<T>(seg_file);
        segment->reopen_segment();
        if (segment->empty()) return false;
        segments[seg_file.path()] = std::move(segment);
    }
    SILKWORM_ASSERT(segments.find(seg_file.path()) != segments.end());
    const auto& segment = segments[seg_file.path()];
    segment->reopen_index();
    return true;
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
            SILK_WARN << "unexpected format for file name: " << file.path().filename() << ", discarded";
        }
    }

    // Order snapshot files by version/block-range/type
    std::sort(snapshot_files.begin(), snapshot_files.end());

    return snapshot_files;
}

BlockNum SnapshotRepository::max_idx_available() const {
    BlockNum max_block_headers{0};
    for (auto& [_, header_seg] : header_segments_) {
        if (not header_seg->idx_header_hash()) break;
        max_block_headers = header_seg->block_to() - 1;
    }
    BlockNum max_block_bodies{0};
    for (auto& [_, body_seg] : body_segments_) {
        if (not body_seg->idx_body_number()) break;
        max_block_bodies = body_seg->block_to() - 1;
    }
    BlockNum max_block_txs{0};
    for (auto& [_, tx_seg] : tx_segments_) {
        if (not tx_seg->idx_txn_hash() or not tx_seg->idx_txn_hash_2_block()) break;
        max_block_txs = tx_seg->block_to() - 1;
    }

    return std::min(max_block_headers, std::min(max_block_bodies, max_block_txs));
}

}  // namespace silkworm::snapshots
