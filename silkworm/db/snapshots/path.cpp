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

#include "path.hpp"

#include <algorithm>
#include <charconv>
#include <string_view>
#include <utility>

#include <absl/strings/str_format.h>
#include <absl/strings/str_replace.h>
#include <absl/strings/str_split.h>
#include <magic_enum.hpp>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

namespace fs = std::filesystem;

std::optional<SnapshotPath> SnapshotPath::parse(fs::path path) {
    const std::string filename_no_ext = path.stem().string();

    // Expected stem format: <version>-<6_digit_block_from>-<6_digit_block_to>-<tag>
    const std::vector<absl::string_view> tokens = absl::StrSplit(filename_no_ext, '-');
    if (tokens.size() != 4) {
        return std::nullopt;
    }

    const auto [ver, scaled_from, scaled_to, tag] = std::tie(tokens[0], tokens[1], tokens[2], tokens[3]);

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
    if (scaled_from.size() != 6 || scaled_to.size() != 6) {
        return std::nullopt;
    }

    BlockNum scaled_block_from{0};
    const auto from_result = std::from_chars(scaled_from.data(), scaled_from.data() + scaled_from.size(), scaled_block_from);
    if (from_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }
    const BlockNum block_from{scaled_block_from * kFileNameBlockScaleFactor};

    BlockNum scaled_block_to{0};
    const auto to_result = std::from_chars(scaled_to.data(), scaled_to.data() + scaled_to.size(), scaled_block_to);
    if (to_result.ec == std::errc::invalid_argument) {
        return std::nullopt;
    }
    const BlockNum block_to{scaled_block_to * kFileNameBlockScaleFactor};

    // Expected proper block range: [block_from, block_to)
    if (block_to < block_from) {
        return std::nullopt;
    }

    // Expected tag format: headers|bodies|transactions (parsing relies on magic_enum, so SnapshotType items must match exactly)
    std::string_view tag_str{tag.data(), tag.size()};
    const auto type = magic_enum::enum_cast<SnapshotType>(tag_str);
    if (!type) {
        return std::nullopt;
    }

    return SnapshotPath{std::move(path), version, block_from, block_to, *type};
}

SnapshotPath SnapshotPath::from(const fs::path& dir, uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type) {
    const auto filename = SnapshotPath::build_filename(version, block_from, block_to, type);
    return SnapshotPath{dir / filename, version, block_from, block_to, type};
}

fs::path SnapshotPath::build_filename(uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type) {
    std::string snapshot_type_name{magic_enum::enum_name(type)};
    std::string filename{absl::StrFormat("v%d-%06d-%06d-%s%s",
                                         version,
                                         block_from / kFileNameBlockScaleFactor,
                                         block_to / kFileNameBlockScaleFactor,
                                         absl::StrReplaceAll(snapshot_type_name, {{"_", "-"}}),
                                         kSegmentExtension)};
    return fs::path{filename};
}

SnapshotPath::SnapshotPath(fs::path path, uint8_t version, BlockNum block_from, BlockNum block_to, SnapshotType type)
    : path_(std::move(path)), version_(version), block_from_(block_from), block_to_(block_to), type_(type) {
    ensure(block_to >= block_from, "SnapshotPath: block_to less than block_from");
}

bool operator<(const SnapshotPath& lhs, const SnapshotPath& rhs) {
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

}  // namespace silkworm::snapshots
