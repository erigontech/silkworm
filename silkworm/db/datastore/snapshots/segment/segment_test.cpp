// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <concepts>
#include <ranges>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

#include "../test_util/string_codec.hpp"
#include "segment_reader.hpp"
#include "segment_writer.hpp"

namespace silkworm::snapshots::segment {

static_assert(std::ranges::input_range<SegmentReader<StringCodec>>);
static_assert(std::movable<SegmentReader<StringCodec>>);

TEST_CASE("SegmentFile") {
    using namespace datastore;
    TemporaryDirectory tmp_dir;
    auto path = SnapshotPath::make(tmp_dir.path(), std::nullopt, SnapshotPath::FilenameFormat::kE2, kSnapshotV1, StepRange{Step{0}, Step{1}}, "headers", ".seg");

    std::vector<std::string> items = {
        "first",
        "second",
        "third",
    };

    SegmentFileWriter file_writer{path, tmp_dir.path()};
    SegmentWriter<StringCodec> writer{file_writer};
    auto out = writer.out();
    for (auto& item : items) {
        *out++ = item;
    }
    SegmentFileWriter::flush(std::move(file_writer));

    SegmentFileReader file_reader{path, {}};
    SegmentReader<StringCodec> reader{file_reader};
    for (std::string& item : reader) {
        CHECK(item == items[0]);
        items.erase(items.begin());
    }
    CHECK(items.empty());
}

}  // namespace silkworm::snapshots::segment
