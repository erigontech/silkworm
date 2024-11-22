/*
   Copyright 2024 The Silkworm Authors

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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

#include "../test_util/string_codec.hpp"
#include "segment_reader.hpp"
#include "segment_writer.hpp"

namespace silkworm::snapshots::segment {

TEST_CASE("SegmentFile") {
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

    SegmentFileReader file_reader{path};
    SegmentReader<StringCodec> reader{file_reader};
    for (std::string& item : reader) {
        CHECK(item == items[0]);
        items.erase(items.begin());
    }
    CHECK(items.empty());
}

}  // namespace silkworm::snapshots::segment
