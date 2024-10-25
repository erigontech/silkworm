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

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/common/directories.hpp>

#include "../test_util/string_codec.hpp"
#include "kv_segment_reader.hpp"
#include "kv_segment_writer.hpp"

namespace silkworm::snapshots {

struct CharCodec : public Encoder, public Decoder {
    char value{};
    Bytes word;

    ~CharCodec() override = default;

    ByteView encode_word() override {
        word.clear();
        word.push_back(*byte_ptr_cast(&value));
        return word;
    }
    void decode_word(ByteView input_word) override {
        value = *byte_ptr_cast(input_word.data());
    }
};

TEST_CASE("KVSegmentFile") {
    TemporaryDirectory tmp_dir;
    auto path = SnapshotPath::make(tmp_dir.path(), kSnapshotV1, StepRange{Step{0}, Step{1}}, SnapshotType::headers);
    static constexpr seg::CompressionKind kCompressionKind = seg::CompressionKind::kKeys;

    std::vector<std::pair<std::string, char>> entries = {
        {"first", 'x'},
        {"second", 'y'},
        {"third", 'z'},
    };

    KVSegmentFileWriter file_writer{path, kCompressionKind, tmp_dir.path()};
    KVSegmentWriter<StringCodec, CharCodec> writer{file_writer};
    auto out = writer.out();
    for (auto& entry : entries) {
        *out++ = entry;
    }
    KVSegmentFileWriter::flush(std::move(file_writer));

    KVSegmentFileReader file_reader{path, kCompressionKind};
    file_reader.reopen_segment();
    KVSegmentReader<StringCodec, CharCodec> reader{file_reader};
    for (std::pair<std::string&, char&> entry : reader) {
        CHECK(entry.first == entries[0].first);
        CHECK(entry.second == entries[0].second);
        entries.erase(entries.begin());
    }
    CHECK(entries.empty());
}

}  // namespace silkworm::snapshots
