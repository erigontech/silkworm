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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::snapshots {

TEST_CASE("SnapshotPath::parse", "[silkworm][node][snapshot]") {
    SECTION("invalid") {
        const char* invalid_filenames[]{
            "",
            ".segment",
            ".seg",
            "u1-014500-015000-headers.seg",
            "-014500-015000-headers.seg",
            "1-014500-015000-headers.seg",
            "v-014500-015000-headers.seg",
            "v1014500-015000-headers.seg",
            "v1-0-015000-headers.seg",
            "v1--015000-headers.seg",
            "v1-014500015000-headers.seg",
            "v1-014500-1-headers.seg",
            "v1-014500-010000-headers.seg",
            "v1-014500--headers.seg",
            "v1-014500-01500a-headers.seg",
            "v1-014500-015000-.seg",
            "v1-014500-015000-unknown.seg",
            "v1-014500-015000headers.seg",
            "v1-014500-015000-headers.seg.seg",
        };
        for (const char* filename : invalid_filenames) {
            CHECK_NOTHROW(SnapshotPath::parse(filename) == std::nullopt);
        }
    }
    SECTION("valid") {
        struct ValidFilenameExpectation {
            const char* filename;
            BlockNum block_from;
            BlockNum block_to;
            SnapshotType type;
        };
        const ValidFilenameExpectation valid_filenames[]{
            {"v1-014500-015000-headers.seg", 14'500'000, 15'000'000, SnapshotType::headers},
            {"v1-011500-012000-bodies.seg", 11'500'000, 12'000'000, SnapshotType::bodies},
            {"v1-018300-018400-transactions.seg", 18'300'000, 18'400'000, SnapshotType::transactions},
        };
        for (const auto& filename_expectation : valid_filenames) {
            const auto snapshot_file = SnapshotPath::parse(filename_expectation.filename);
            CHECK(snapshot_file != std::nullopt);
            if (snapshot_file) {
                CHECK(snapshot_file->path() == filename_expectation.filename);
                CHECK(snapshot_file->version() == 1);
                CHECK(snapshot_file->block_from() == filename_expectation.block_from);
                CHECK(snapshot_file->block_to() == filename_expectation.block_to);
                CHECK(snapshot_file->segment_size() == filename_expectation.block_to - filename_expectation.block_from);
                CHECK(snapshot_file->type() == filename_expectation.type);
                CHECK(snapshot_file->seedable());
                CHECK(!snapshot_file->exists_torrent_file());
                CHECK(snapshot_file->torrent_file_needed());
                const SnapshotPath index_file = snapshot_file->index_file();
                CHECK(index_file.path().stem() == snapshot_file->path().stem());
                CHECK(index_file.path().extension() == kIdxExtension);
                CHECK(index_file.version() == 1);
                CHECK(index_file.block_from() == filename_expectation.block_from);
                CHECK(index_file.block_to() == filename_expectation.block_to);
                CHECK(index_file.type() == filename_expectation.type);
            }
        }
    }
}

TEST_CASE("SnapshotPath::from", "[silkworm][node][snapshot]") {
    SECTION("invalid") {
        CHECK_THROWS_AS(SnapshotPath::from(std::filesystem::path{}, kSnapshotV1, 1'000, 999, SnapshotType::headers),
                        std::logic_error);
    }
}

}  // namespace silkworm::snapshots
