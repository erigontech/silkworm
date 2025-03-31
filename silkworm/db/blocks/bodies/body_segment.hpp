// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    void decode_word(Word& word) override {
        decode_word_into_body(word, value);
    }
};

static_assert(DecoderConcept<BodySegmentWordDecoder>);

using BodySegmentReader = segment::SegmentReader<BodySegmentWordDecoder>;
using BodySegmentWriter = segment::SegmentWriter<BodySegmentWordEncoder>;

}  // namespace silkworm::snapshots
