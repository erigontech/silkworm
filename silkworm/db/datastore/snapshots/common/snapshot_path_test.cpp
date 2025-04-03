// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "snapshot_path.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::snapshots {

using namespace datastore;

TEST_CASE("SnapshotPath::parse", "[silkworm][node][snapshot]") {
    SECTION("invalid") {
        static constexpr std::string_view kInvalidFilenames[]{
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
        for (const auto& filename : kInvalidFilenames) {
            CHECK_NOTHROW(SnapshotPath::parse(filename) == std::nullopt);
        }
    }

    SECTION("valid") {
        struct TestExample {
            std::string filename;
            StepRange expected_range;
            std::string expected_tag;
        };
        static const TestExample kExamples[]{
            {"v1-014500-015000-headers.seg", {Step{14'500}, Step{15'000}}, "headers"},
            {"v1-011500-012000-bodies.seg", {Step{11'500}, Step{12'000}}, "bodies"},
            {"v1-018300-018400-transactions.seg", {Step{18'300}, Step{18'400}}, "transactions"},
            {"v1-018300-018400-transactions-to-block.idx", {Step{18'300}, Step{18'400}}, "transactions-to-block"},
            {"v1-commitment.0-1024.kv", {Step{0}, Step{1'024}}, "commitment"},
            {"v1-receipt.64-128.ef", {Step{64}, Step{128}}, "receipt"},
            {"v1-storage.1672-1673.vi", {Step{1'672}, Step{1'673}}, "storage"},
        };
        for (const auto& example : kExamples) {
            const auto path = SnapshotPath::parse(example.filename);
            REQUIRE(path);
            CHECK(path->filename() == example.filename);
            CHECK(path->version() == 1);
            CHECK(path->step_range() == example.expected_range);
            CHECK(path->tag() == example.expected_tag);
        }
    }

    SECTION("directory-E2") {
        auto path = SnapshotPath::parse("/snapshots/v1-001000-002000-headers.seg");
        REQUIRE(path);
        CHECK(path->base_dir_path() == "/snapshots");
        CHECK_FALSE(path->sub_dir_name());
    }

    SECTION("directory-E3") {
        auto path = SnapshotPath::parse("/snapshots/accessor/v1-storage.5-155.vi", "/snapshots");
        REQUIRE(path);
        CHECK(path->base_dir_path() == "/snapshots");
        CHECK(path->sub_dir_name() == "accessor");
    }
}

TEST_CASE("SnapshotPath::make", "[silkworm][node][snapshot]") {
    CHECK(
        SnapshotPath::make(
            "/snapshots", std::nullopt,
            SnapshotPath::FilenameFormat::kE2, kSnapshotV1,
            StepRange{Step{1'000}, Step{2'000}},
            "headers", ".seg")
            .path() == "/snapshots/v1-001000-002000-headers.seg");
    CHECK(
        SnapshotPath::make(
            "/snapshots", "accessor",
            SnapshotPath::FilenameFormat::kE3, kSnapshotV1,
            StepRange{Step{5}, Step{155}},
            "storage", ".vi")
            .path() == "/snapshots/accessor/v1-storage.5-155.vi");
}

TEST_CASE("StepRange invalid") {
    CHECK_THROWS_AS((StepRange{Step{1'000}, Step{999}}), std::logic_error);
}

}  // namespace silkworm::snapshots
