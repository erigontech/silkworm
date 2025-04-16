// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "inverted_index_ts_list_codec.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/kv_segment_reader.hpp"

namespace silkworm::snapshots {

struct InvertedIndex {
    const segment::KVSegmentFileReader& kv_segment;
    const rec_split::AccessorIndex& accessor_index;

    template <DecoderConcept TKeyDecoder>
    segment::KVSegmentReader<TKeyDecoder, InvertedIndexTimestampListDecoder> kv_segment_reader() {
        return segment::KVSegmentReader<TKeyDecoder, InvertedIndexTimestampListDecoder>{kv_segment};
    }
};

}  // namespace silkworm::snapshots
