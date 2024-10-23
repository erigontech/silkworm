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
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_writer.hpp>

namespace silkworm::snapshots {

void encode_word_from_body(Bytes& word, const BlockBodyForStorage& body);
void decode_word_into_body(ByteView word, BlockBodyForStorage& body);

struct BodySegmentWordEncoder : public Encoder {
    BlockBodyForStorage value;
    Bytes word;

    ~BodySegmentWordEncoder() override = default;

    ByteView encode_word() override {
        word.clear();
        encode_word_from_body(word, value);
        return word;
    }
};

static_assert(EncoderConcept<BodySegmentWordEncoder>);

struct BodySegmentWordDecoder : public Decoder {
    BlockBodyForStorage value;

    ~BodySegmentWordDecoder() override = default;

    void decode_word(ByteView word) override {
        decode_word_into_body(word, value);
    }
};

static_assert(DecoderConcept<BodySegmentWordDecoder>);

using BodySegmentReader = SegmentReader<BodySegmentWordDecoder>;
using BodySegmentWriter = SegmentWriter<BodySegmentWordEncoder>;

}  // namespace silkworm::snapshots
