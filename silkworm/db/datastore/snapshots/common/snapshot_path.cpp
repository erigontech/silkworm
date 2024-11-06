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

#include <absl/strings/str_format.h>
#include <absl/strings/str_split.h>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

namespace fs = std::filesystem;

std::optional<StepRange> SnapshotPath::parse_step_range(const fs::path& path) {
    const std::string filename_no_ext = path.stem().string();

    // Expected stem format: <version>-<6_digit_block_from>-<6_digit_block_to>-<tag>
    const std::vector<absl::string_view> tokens = absl::StrSplit(filename_no_ext, absl::MaxSplits('-', 3));
    if (tokens.size() != 4) {
        return std::nullopt;
    }

    const auto [ver, from, to, tag] = std::tie(tokens[0], tokens[1], tokens[2], tokens[3]);

    // Expected scaled block format: <dddddd>
    if (from.size() != 6 || to.size() != 6) {
        return std::nullopt;
    }

    Step step_from{0};
    const auto from_result = std::from_chars(from.data(), from.data() + from.size(), step_from.value);
    if (from_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }

    Step step_to{0};
    const auto to_result = std::from_chars(to.data(), to.data() + to.size(), step_to.value);
    if (to_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }

    // Expected proper range: [from, to)
    if (step_to < step_from) {
        return std::nullopt;
    }

    return StepRange{step_from, step_to};
}

std::optional<SnapshotPath> SnapshotPath::parse(fs::path path) {
    const std::string filename_no_ext = path.stem().string();

    // Expected stem format: <version>-<6_digit_block_from>-<6_digit_block_to>-<tag>
    const std::vector<absl::string_view> tokens = absl::StrSplit(filename_no_ext, absl::MaxSplits('-', 3));
    if (tokens.size() != 4) {
        return std::nullopt;
    }

    const auto [ver, from, to, tag] = std::tie(tokens[0], tokens[1], tokens[2], tokens[3]);

    // Expected version format: v<x> (hence check length, check first char and parse w/ offset by one)
    if (ver.empty() || ver[0] != 'v') {
        return std::nullopt;
    }

    uint8_t ver_num = 0;
    const auto ver_result = std::from_chars(ver.data() + 1, ver.data() + ver.size(), ver_num);
    if (ver_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }

    auto step_range = parse_step_range(path);
    if (!step_range) {
        return std::nullopt;
    }

    return SnapshotPath{std::move(path), ver_num, *step_range, std::string{tag}};
}

SnapshotPath SnapshotPath::make(
    const fs::path& dir,
    uint8_t version,
    StepRange step_range,
    std::string tag,
    std::string_view ext) {
    const auto filename = SnapshotPath::make_filename(version, step_range, tag, ext);
    return SnapshotPath{dir / filename, version, step_range, std::move(tag)};
}

fs::path SnapshotPath::make_filename(
    uint8_t version,
    StepRange step_range,
    std::string_view tag,
    std::string_view ext) {
    std::string filename = absl::StrFormat(
        "v%d-%06d-%06d-%s%s",
        version,
        step_range.start.value,
        step_range.end.value,
        tag,
        ext);
    return fs::path{filename};
}

SnapshotPath SnapshotPath::related_path(std::string tag, std::string_view ext) const {
    return SnapshotPath::make(path_.parent_path(), version_, step_range_, std::move(tag), ext);
}

SnapshotPath::SnapshotPath(
    fs::path path,
    uint8_t version,
    StepRange step_range,
    std::string tag)
    : path_{std::move(path)},
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
