// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_writer.hpp>

namespace silkworm::snapshots {

void encode_word_from_header(Bytes& word, const BlockHeader& header);
void decode_word_into_header(ByteView word, BlockHeader& header);
void check_sanity_of_header_with_metadata(const BlockHeader& header, datastore::StepRange step_range);

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

    void decode_word(Word& word) override {
        decode_word_into_header(word, value);
    }

    void check_sanity_with_metadata(const SnapshotPath& path) override {
        check_sanity_of_header_with_metadata(value, path.step_range());
    }
};

static_assert(DecoderConcept<HeaderSegmentWordDecoder>);

using HeaderSegmentReader = segment::SegmentReader<HeaderSegmentWordDecoder>;
using HeaderSegmentWriter = segment::SegmentWriter<HeaderSegmentWordEncoder>;

}  // namespace silkworm::snapshots
