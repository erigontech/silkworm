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

#pragma once

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_writer.hpp>

namespace silkworm::snapshots {

void encode_word_from_header(Bytes& word, const BlockHeader& header);
void decode_word_into_header(ByteView word, BlockHeader& header);
void check_sanity_of_header_with_metadata(const BlockHeader& header, BlockNumRange block_num_range);

struct HeaderSegmentWordEncoder : public Encoder {
    BlockHeader value;
    Bytes word;

    ~HeaderSegmentWordEncoder() override = default;

    ByteView encode_word() override {
        word.clear();
        encode_word_from_header(word, value);
        return word;
    }
};

static_assert(EncoderConcept<HeaderSegmentWordEncoder>);

struct HeaderSegmentWordDecoder : public Decoder {
    BlockHeader value;

    ~HeaderSegmentWordDecoder() override = default;

    void decode_word(BytesOrByteView& word) override {
        decode_word_into_header(word.byte_view(), value);
    }

    void check_sanity_with_metadata(const SnapshotPath& path) override {
        check_sanity_of_header_with_metadata(value, path.step_range().to_block_num_range());
    }
};

static_assert(DecoderConcept<HeaderSegmentWordDecoder>);

using HeaderSegmentReader = segment::SegmentReader<HeaderSegmentWordDecoder>;
using HeaderSegmentWriter = segment::SegmentWriter<HeaderSegmentWordEncoder>;

}  // namespace silkworm::snapshots
