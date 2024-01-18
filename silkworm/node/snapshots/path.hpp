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
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm::snapshots {

//! The scale factor to convert the block numbers to/from the values in snapshot file names
constexpr int kFileNameBlockScaleFactor{1'000};

//! The segment size measured as number of blocks included in each segment
constexpr uint64_t kDefaultSegmentSize{500'000};

//! The minimum segment size measured as number of blocks included in each segment
constexpr uint64_t kMinimumSegmentSize{kFileNameBlockScaleFactor};

constexpr const char* kTorrentExtension{".torrent"};
constexpr const char* kSegmentExtension{".seg"};
constexpr const char* kIdxExtension{".idx"};
constexpr const char* kTmpExtension{".tmp"};

//! The snapshot category corresponding to the snapshot file type
//! @remark item names do NOT follow Google style to obtain the tag used in file names from magic_enum::enum_name
//! @see SnapshotPath#build_filename
enum SnapshotType {
    headers = 0,
    bodies = 1,
    transactions = 2,
    transactions_to_block = 3,
};

//! The snapshot version 1 aka v1
constexpr uint8_t kSnapshotV1{1};

class SnapshotPath {
  public:
    [[nodiscard]] static uint64_t segment_size() { return segment_size_; }

    [[nodiscard]] static std::optional<SnapshotPath> parse(std::filesystem::path path);

    [[nodiscard]] static SnapshotPath from(const std::filesystem::path& dir,
                                           uint8_t version,
                                           BlockNum block_from,
                                           BlockNum block_to,
                                           SnapshotType type);

    [[nodiscard]] std::string filename() const { return path_.filename().string(); }

    [[nodiscard]] std::filesystem::path path() const { return path_; }

    [[nodiscard]] uint8_t version() const { return version_; }

    [[nodiscard]] BlockNum block_from() const { return block_from_; }

    [[nodiscard]] BlockNum block_to() const { return block_to_; }

    [[nodiscard]] SnapshotType type() const { return type_; }

    [[nodiscard]] bool is_segment() const { return path_.extension().string() == kSegmentExtension; }

    [[nodiscard]] bool exists() const {
        return std::filesystem::exists(std::filesystem::path{path_});
    }

    [[nodiscard]] bool exists_torrent_file() const {
        return std::filesystem::exists(std::filesystem::path{path_ / kTorrentExtension});
    }

    [[nodiscard]] bool seedable() const {
        return block_to_ - block_from_ == segment_size_;
    }

    [[nodiscard]] bool torrent_file_needed() const {
        return seedable() && !exists_torrent_file();
    }

    [[nodiscard]] SnapshotPath index_file() const {
        return SnapshotPath(std::filesystem::path{path_}.replace_extension(kIdxExtension), version_, block_from_, block_to_, type_);
    }

    [[nodiscard]] SnapshotPath index_file_for_type(SnapshotType type) const {
        std::filesystem::path index_path{path_};
        index_path.replace_filename(build_filename(version_, block_from_, block_to_, type));
        return SnapshotPath(index_path.replace_extension(kIdxExtension), version_, block_from_, block_to_, type);
    }

    friend bool operator<(const SnapshotPath& lhs, const SnapshotPath& rhs);

  protected:
    static std::filesystem::path build_filename(uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type);

    inline static uint64_t segment_size_{kDefaultSegmentSize};

    explicit SnapshotPath(std::filesystem::path path, uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type);

    std::filesystem::path path_;
    uint8_t version_{0};
    BlockNum block_from_{0};
    BlockNum block_to_{0};
    SnapshotType type_;
};

using SnapshotPathList = std::vector<SnapshotPath>;

}  // namespace silkworm::snapshots
