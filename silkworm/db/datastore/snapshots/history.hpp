// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "history_accessor_index.hpp"
#include "inverted_index.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/segment_reader.hpp"
#include "segment_and_accessor_index.hpp"

namespace silkworm::snapshots {

struct History {
    const segment::SegmentFileReader& segment;
    const rec_split::AccessorIndex& accessor_index;
    InvertedIndex inverted_index;

    template <EncoderConcept TIIKeyEncoder>
    static HistoryAccessorIndexKeyEncoder<TIIKeyEncoder> make_accessor_index_key_encoder() {
        return HistoryAccessorIndexKeyEncoder<TIIKeyEncoder>{};
    }

    SegmentAndAccessorIndex segment_and_index() const {
        return {segment, accessor_index};
    }
};

}  // namespace silkworm::snapshots
