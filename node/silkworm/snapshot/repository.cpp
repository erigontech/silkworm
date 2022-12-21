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
#include <charconv>
#include <ranges>
#include <string_view>
#include <utility>

#include <absl/strings/str_split.h>
#include <magic_enum.hpp>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

//! The scale factor to convert the block numbers to/from the values in snapshot file names
constexpr int kFileNameBlockScaleFactor{1'000};

namespace fs = std::filesystem;

std::optional<SnapshotFile> SnapshotFile::parse(std::filesystem::path path) {
    const std::string filename_no_ext = path.stem().string();

    // Expected stem format: <version>-<6_digit_block_from>-<6_digit_block_to>-<tag>
    const std::vector<std::string_view> tokens = absl::StrSplit(filename_no_ext, "-");
    if (tokens.size() != 4) {
        return std::nullopt;
    }

    const auto [ver, from, to, tag] = std::tie(tokens[0], tokens[1], tokens[2], tokens[3]);

    // Expected version format: v<x> (hence check length, check first char and parse w/ offset by one)
    if (ver.empty() || ver[0] != 'v') {
        return std::nullopt;
    }

    uint8_t version{0};
    const auto ver_result = std::from_chars(ver.data() + 1, ver.data() + ver.size(), version);
    if (ver_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }

    // Expected scaled block format: <dddddd>
    BlockNum scaled_block_from{0};
    const auto from_result = std::from_chars(from.data(), from.data() + from.size(), scaled_block_from);
    if (from_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }
    const BlockNum block_from{scaled_block_from * kFileNameBlockScaleFactor};

    BlockNum scaled_block_to{0};
    const auto to_result = std::from_chars(to.data(), to.data() + to.size(), scaled_block_to);
    if (to_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }
    const BlockNum block_to{scaled_block_to * kFileNameBlockScaleFactor};

    // Expected tag format: headers|bodies|transactions (parsing relies on magic_enum, so SnapshotType items must match exactly)
    const auto type = magic_enum::enum_cast<SnapshotType>(tag);
    if (!type) {
        return std::nullopt;
    }

    return SnapshotFile{std::move(path), version, block_from, block_to, *type};
}

SnapshotFile::SnapshotFile(std::filesystem::path path, uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type)
    : path_(std::move(path)), version_(version), block_from_(block_from), block_to_(block_to), type_(type) {}

bool operator<(const SnapshotFile& lhs, const SnapshotFile& rhs) {
    if (lhs.version_ != rhs.version_) {
        return lhs.version_ < rhs.version_;
    }
    if (lhs.block_from_ != rhs.block_from_) {
        return lhs.block_from_ < rhs.block_from_;
    }
    if (lhs.block_to_ != rhs.block_to_) {
        return lhs.block_to_ < rhs.block_to_;
    }
    if (lhs.type_ != rhs.type_) {
        return lhs.type_ < rhs.type_;
    }
    return lhs.path_.extension() < rhs.path_.extension();
}

SnapshotRepository::SnapshotRepository(SnapshotSettings settings) : settings_(std::move(settings)) {}

void SnapshotRepository::reopen_folder() {
    SILK_INFO << "Reopen snapshot repository folder: " << settings_.repository_dir.string();
    SnapshotFileList segment_files = get_segment_files();
    reopen_list(segment_files, /*.optimistic=*/false);
}

bool SnapshotRepository::for_each_header(const HeaderSnapshot::Walker& fn) {
    for (const auto& [_, header_snapshot] : header_segments_) {
        SILK_DEBUG << "for_each_header header_snapshot: " << header_snapshot->path().string();
        const auto keep_going = header_snapshot->for_each_header([fn](const auto* header) {
            return fn(header);
        });
        if (!keep_going) return false;
    }
    return true;
}

bool SnapshotRepository::for_each_body(const BodySnapshot::Walker& fn) {
    for (const auto& [_, body_snapshot] : body_segments_) {
        SILK_DEBUG << "for_each_body body_snapshot: " << body_snapshot->path().string();
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

void SnapshotRepository::reopen_list(const SnapshotFileList& segment_files, bool optimistic) {
    close_segments_not_in_list(segment_files);

    BlockNum segment_max_block{0};
    for (const auto& seg_file : segment_files) {
        try {
            SILK_INFO << "Reopen segment file: " << seg_file.path();
            bool snapshot_added{false};
            switch (seg_file.type()) {
                case SnapshotType::headers: {
                    snapshot_added = reopen_header(seg_file);
                    break;
                }
                case SnapshotType::bodies: {
                    snapshot_added = reopen_body(seg_file);
                    break;
                }
                case SnapshotType::transactions: {
                    snapshot_added = reopen_transaction(seg_file);
                    break;
                }
                default: {
                    SILKWORM_ASSERT(false);
                }
            }

            if (snapshot_added && seg_file.block_to() > segment_max_block) {
                segment_max_block = seg_file.block_to();
            }
        } catch (const std::exception& exc) {
            SILK_WARN << "Reopen failed for: " << seg_file.path() << " [" << exc.what() << "]";
            if (!optimistic) throw;
        }
    }
    segment_max_block_ = segment_max_block;
    idx_max_block_ = max_idx_available();
}

bool SnapshotRepository::reopen_header(const SnapshotFile& seg_file) {
    return reopen(header_segments_, seg_file);
}

bool SnapshotRepository::reopen_body(const SnapshotFile& seg_file) {
    return reopen(body_segments_, seg_file);
}

bool SnapshotRepository::reopen_transaction(const SnapshotFile& seg_file) {
    return reopen(tx_segments_, seg_file);
}

void SnapshotRepository::close_segments_not_in_list(const SnapshotFileList& /*segment_files*/) {
    // TODO(canepat): implement
}

template <ConcreteSnapshot T>
SnapshotRepository::ViewResult SnapshotRepository::view(const SnapshotsByPath<T>& segments, BlockNum number,
                                                        const SnapshotWalker<T>& walker) {
    for (const auto& [_, snapshot] : segments) {
        if (snapshot->block_from() <= number && number < snapshot->block_to()) {
            const bool walk_done = walker(snapshot.get());
            return walk_done ? kWalkSuccess : kWalkFailed;
        }
    }
    return kSnapshotNotFound;
}

template <ConcreteSnapshot T>
bool SnapshotRepository::reopen(SnapshotsByPath<T>& segments, const SnapshotFile& seg_file) {
    if (segments.find(seg_file.path()) == segments.end()) {
        auto segment = std::make_unique<T>(seg_file.path(), seg_file.block_from(), seg_file.block_to());
        segment->reopen_segment();
        if (segment->empty()) return false;
        segments[seg_file.path()] = std::move(segment);
    }
    SILKWORM_ASSERT(segments.find(seg_file.path()) != segments.end());
    const auto& segment = segments[seg_file.path()];
    segment->reopen_index();
    return true;
}

SnapshotFileList SnapshotRepository::get_files(const std::string& ext) const {
    SILKWORM_ASSERT(fs::exists(settings_.repository_dir) && fs::is_directory(settings_.repository_dir));

    // Load the resulting files w/ desired extension ensuring they are snapshots
    SnapshotFileList snapshot_files;
    for (const auto& file : fs::directory_iterator{settings_.repository_dir}) {
        if (!fs::is_regular_file(file.path()) || file.path().extension().string() != ext) {
            continue;
        }
        SILK_DEBUG << "Path: " << file.path() << " name: " << file.path().filename();
        const auto snapshot_file = SnapshotFile::parse(file);
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

uint64_t SnapshotRepository::max_idx_available() const {
    // TODO(canepat): implement
    return 0;
}

}  // namespace silkworm
