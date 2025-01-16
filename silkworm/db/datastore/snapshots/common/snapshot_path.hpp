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

#include "../../common/step.hpp"

namespace silkworm::snapshots {

//! The snapshot version 1 aka v1
inline constexpr uint8_t kSnapshotV1{1};

class SnapshotPath {
  public:
    using StepRange = datastore::StepRange;

    enum class FilenameFormat {
        kE2,
        kE3,
    };

    static std::optional<SnapshotPath> parse(std::filesystem::path path);
    static std::optional<SnapshotPath> parse(
        std::filesystem::path path,
        const std::filesystem::path& base_dir);

    static SnapshotPath make(
        const std::filesystem::path& base_dir,
        std::optional<std::string> sub_dir_name,
        FilenameFormat filename_format,
        uint8_t version,
        StepRange step_range,
        std::string tag,
        std::string_view ext);

    std::string filename() const { return path_.filename().string(); }
    const std::filesystem::path& path() const { return path_; }
    std::filesystem::path base_dir_path() const {
        auto dir = path_.parent_path();
        return sub_dir_name_ ? dir.parent_path() : dir;
    }
    const std::optional<std::string>& sub_dir_name() const { return sub_dir_name_; }
    std::string extension() const { return path_.extension().string(); }
    uint8_t version() const { return version_; }
    StepRange step_range() const { return step_range_; }
    const std::string& tag() const { return tag_; }
    bool exists() const { return std::filesystem::exists(path_); }

    SnapshotPath related_path(std::string tag, std::string_view ext) const;
    SnapshotPath related_path_ext(std::string_view ext) const {
        return related_path(tag_, ext);
    }

    friend bool operator<(const SnapshotPath& lhs, const SnapshotPath& rhs);
    friend bool operator==(const SnapshotPath&, const SnapshotPath&) = default;

  protected:
    static std::filesystem::path make_filename(
        FilenameFormat format,
        uint8_t version,
        StepRange step_range,
        std::string_view tag,
        std::string_view ext);

    SnapshotPath(
        std::filesystem::path path,
        std::optional<std::string> sub_dir_name,
        FilenameFormat filename_format,
        uint8_t version,
        StepRange step_range,
        std::string tag);

    std::filesystem::path path_;
    std::optional<std::string> sub_dir_name_;
    FilenameFormat filename_format_;
    uint8_t version_{0};
    StepRange step_range_;
    std::string tag_;
};

using SnapshotPathList = std::vector<SnapshotPath>;

}  // namespace silkworm::snapshots
