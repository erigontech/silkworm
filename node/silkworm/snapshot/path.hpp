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

#include <silkworm/common/base.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

constexpr const char* kDefaultSnapshotDir{"snapshots"};

constexpr uint64_t kDefaultSegmentSize{500'000};
constexpr uint64_t kMinimumSegmentSize{1'000};

constexpr const char* kTorrentExtension{".torrent"};
constexpr const char* kSegmentExtension{".seg"};
constexpr const char* kIdxExtension{".idx"};
constexpr const char* kTmpExtension{".tmp"};

//! The snapshot category
//! @remark item names do NOT follow Google style just to make magic_enum work
enum SnapshotType {
    headers = 0,
    bodies = 1,
    transactions = 2,
    transactions2block = 3,
};

class SnapshotFile {
  public:
    [[nodiscard]] static std::optional<SnapshotFile> parse(std::filesystem::path path);

    [[nodiscard]] static SnapshotFile from(const std::filesystem::path& dir,
                                           uint8_t version,
                                           BlockNum block_from,
                                           BlockNum block_to,
                                           SnapshotType type);

    [[nodiscard]] std::filesystem::path path() const { return path_; }

    [[nodiscard]] uint8_t version() const { return version_; }

    [[nodiscard]] BlockNum block_from() const { return block_from_; }

    [[nodiscard]] BlockNum block_to() const { return block_to_; }

    [[nodiscard]] SnapshotType type() const { return type_; }

    [[nodiscard]] bool exists_torrent_file() const {
        return std::filesystem::exists(std::filesystem::path{path_ / kTorrentExtension});
    }

    [[nodiscard]] bool seedable() const {
        return block_to_ - block_from_ == kDefaultSegmentSize;
    }

    [[nodiscard]] bool torrent_file_needed() const {
        return seedable() && !exists_torrent_file();
    }

    [[nodiscard]] SnapshotFile index_file() const {
        return SnapshotFile(std::filesystem::path{path_}.replace_extension(kIdxExtension), version_, block_from_, block_to_, type_);
    }

    [[nodiscard]] SnapshotFile index_file_for_type(SnapshotType type) const {
        std::filesystem::path index_path{path_};
        index_path.replace_filename(build_filename(version_, block_from_, block_to_, type));
        return SnapshotFile(index_path.replace_extension(kIdxExtension), version_, block_from_, block_to_, type);
    }

    friend bool operator<(const SnapshotFile& lhs, const SnapshotFile& rhs);

  protected:
    static std::filesystem::path build_filename(uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type);

    explicit SnapshotFile(std::filesystem::path path, uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type);

    std::filesystem::path path_;
    uint8_t version_{0};
    BlockNum block_from_{0};
    BlockNum block_to_{0};
    SnapshotType type_;
};

using SnapshotFileList = std::vector<SnapshotFile>;

}  // namespace silkworm
