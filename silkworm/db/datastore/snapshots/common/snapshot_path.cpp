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

#include "snapshot_path.hpp"

#include <algorithm>
#include <charconv>
#include <regex>

#include <absl/strings/str_format.h>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

namespace fs = std::filesystem;

std::optional<SnapshotPath> SnapshotPath::parse(fs::path path) {
    auto base_dir = path.parent_path();
    return parse(std::move(path), base_dir);
}

std::optional<SnapshotPath> SnapshotPath::parse(
    fs::path path,
    const fs::path& base_dir) {
    auto filename = path.filename().string();

    // example: v1-009960-009970-transactions-to-block.idx
    static const std::regex kFilenameRegexE2{R"(v(\d)-(\d{6})-(\d{6})-([\w\-]+)\.\w+)"};
    // example: v1-commitment.0-1024.kv
    static const std::regex kFilenameRegexE3{R"(v(\d)-([\w\-]+)\.(\d{1,6})-(\d{1,6})\.\w+)"};

    FilenameFormat filename_format = FilenameFormat::kE2;
    int step_start = 0;
    int step_end = 0;
    std::string tag;

    std::smatch matches;
    if (std::regex_match(filename, matches, kFilenameRegexE2)) {
        filename_format = FilenameFormat::kE2;
        step_start = std::stoi(matches[2]);
        step_end = std::stoi(matches[3]);
        tag = matches[4].str();
    } else if (std::regex_match(filename, matches, kFilenameRegexE3)) {
        filename_format = FilenameFormat::kE3;
        step_start = std::stoi(matches[3]);
        step_end = std::stoi(matches[4]);
        tag = matches[2].str();
    } else {
        return std::nullopt;
    }

    uint8_t version = static_cast<uint8_t>(std::stoi(matches[1]));

    if (step_start > step_end) {
        return std::nullopt;
    }
    StepRange step_range{
        datastore::Step{static_cast<size_t>(step_start)},
        datastore::Step{static_cast<size_t>(step_end)},
    };

    std::optional<std::string> sub_dir_name;
    if (base_dir == path.parent_path()) {
        sub_dir_name = std::nullopt;
    } else if (base_dir == path.parent_path().parent_path()) {
        sub_dir_name = path.parent_path().filename().string();
    } else {
        return std::nullopt;
    }

    return SnapshotPath{
        std::move(path),
        std::move(sub_dir_name),
        filename_format,
        version,
        step_range,
        std::move(tag),
    };
}

SnapshotPath SnapshotPath::make(
    const fs::path& base_dir,
    std::optional<std::string> sub_dir_name,
    FilenameFormat filename_format,
    uint8_t version,
    StepRange step_range,
    std::string tag,
    std::string_view ext) {
    auto path = base_dir;
    if (sub_dir_name) {
        path /= *sub_dir_name;
    }
    path /= SnapshotPath::make_filename(filename_format, version, step_range, tag, ext);

    return SnapshotPath{
        std::move(path),
        std::move(sub_dir_name),
        filename_format,
        version,
        step_range,
        std::move(tag),
    };
}

fs::path SnapshotPath::make_filename(
    FilenameFormat format,
    uint8_t version,
    StepRange step_range,
    std::string_view tag,
    std::string_view ext) {
    switch (format) {
        case FilenameFormat::kE2:
            // example: v1-009960-009970-transactions-to-block.idx
            return absl::StrFormat(
                "v%d-%06d-%06d-%s%s",
                version,
                step_range.start.value,
                step_range.end.value,
                tag,
                ext);
        case FilenameFormat::kE3:
            // example: v1-commitment.0-1024.kv
            return absl::StrFormat(
                "v%d-%s.%d-%d%s",
                version,
                tag,
                step_range.start.value,
                step_range.end.value,
                ext);
        default:
            SILKWORM_ASSERT(false);
            return {};
    }
}

SnapshotPath SnapshotPath::related_path(std::string tag, std::string_view ext) const {
    return SnapshotPath::make(base_dir_path(), sub_dir_name_, filename_format_, version_, step_range_, std::move(tag), ext);
}

SnapshotPath::SnapshotPath(
    fs::path path,
    std::optional<std::string> sub_dir_name,
    FilenameFormat filename_format,
    uint8_t version,
    StepRange step_range,
    std::string tag)
    : path_{std::move(path)},
      sub_dir_name_{std::move(sub_dir_name)},
      filename_format_{filename_format},
      version_{version},
      step_range_{step_range},
      tag_{std::move(tag)} {
}

bool operator<(const SnapshotPath& lhs, const SnapshotPath& rhs) {
    if (lhs.version_ != rhs.version_) {
        return lhs.version_ < rhs.version_;
    }
    if (lhs.step_range_.start != rhs.step_range_.start) {
        return lhs.step_range_.start < rhs.step_range_.start;
    }
    if (lhs.step_range_.end != rhs.step_range_.end) {
        return lhs.step_range_.end < rhs.step_range_.end;
    }
    if (lhs.tag_ != rhs.tag_) {
        return lhs.tag_ < rhs.tag_;
    }
    return lhs.path_.extension() < rhs.path_.extension();
}

}  // namespace silkworm::snapshots
