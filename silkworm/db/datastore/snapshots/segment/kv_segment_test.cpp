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

namespace silkworm::snapshots::segment {

struct CharCodec : public Codec {
    char value{};
    Bytes word;

    ~CharCodec() override = default;

    ByteView encode_word() override {
        word.clear();
        word.push_back(*byte_ptr_cast(&value));
        return word;
    }
    void decode_word(Word& input_word) override {
        auto input_word_view = input_word.byte_view();
        if (input_word_view.empty()) {
            throw std::runtime_error{"CharCodec failed to decode"};
        }
        value = *byte_ptr_cast(input_word_view.data());
    }
};

TEST_CASE("KVSegmentFile") {
    using namespace datastore;
    TemporaryDirectory tmp_dir;
    auto path = SnapshotPath::make(tmp_dir.path(), std::nullopt, SnapshotPath::FilenameFormat::kE2, kSnapshotV1, StepRange{Step{0}, Step{1}}, "headers", ".seg");
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
    KVSegmentReader<StringCodec, CharCodec> reader{file_reader};
    for (std::pair<std::string&, char&> entry : reader) {
        CHECK(entry.first == entries[0].first);
        CHECK(entry.second == entries[0].second);
        entries.erase(entries.begin());
    }
    CHECK(entries.empty());
}

}  // namespace silkworm::snapshots::segment
