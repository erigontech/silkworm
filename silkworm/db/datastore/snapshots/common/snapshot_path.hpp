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

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "snapshot_type.hpp"
#include "step.hpp"

namespace silkworm::snapshots {

inline constexpr const char* kSegmentExtension{".seg"};
inline constexpr const char* kIdxExtension{".idx"};

//! The snapshot version 1 aka v1
inline constexpr uint8_t kSnapshotV1{1};

class SnapshotPath {
  public:
    static std::optional<SnapshotPath> parse(std::filesystem::path path);
    static std::optional<StepRange> parse_step_range(const std::filesystem::path& path);

    static SnapshotPath make(
        const std::filesystem::path& dir,
        uint8_t version,
        StepRange step_range,
        std::string tag,
        const char* ext = kSegmentExtension);

    std::string filename() const { return path_.filename().string(); }
    const std::filesystem::path& path() const { return path_; }
    std::string extension() const { return path_.extension().string(); }
    uint8_t version() const { return version_; }
    StepRange step_range() const { return step_range_; }
    const std::string& tag() const { return tag_; }
    bool exists() const { return std::filesystem::exists(path_); }

    SnapshotPath related_path(std::string tag, const char* ext) const;
    SnapshotPath index_file() const {
        return related_path(tag_, kIdxExtension);
    }

    friend bool operator<(const SnapshotPath& lhs, const SnapshotPath& rhs);
    friend bool operator==(const SnapshotPath&, const SnapshotPath&) = default;

  protected:
    static std::filesystem::path make_filename(
        uint8_t version,
        StepRange step_range,
        std::string tag,
        const char* ext);

    SnapshotPath(
        std::filesystem::path path,
        uint8_t version,
        StepRange step_range,
        std::string tag,
        SnapshotType type);

    std::filesystem::path path_;
    uint8_t version_{0};
    StepRange step_range_;
    std::string tag_;
    SnapshotType type_;
};

using SnapshotPathList = std::vector<SnapshotPath>;

}  // namespace silkworm::snapshots
