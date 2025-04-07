// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "elias_fano/elias_fano_decoder.hpp"
#include "rec_split/accessor_index.hpp"
#include "segment/kv_segment_reader.hpp"

namespace silkworm::snapshots {

struct InvertedIndex {
    const segment::KVSegmentFileReader& kv_segment;
    const rec_split::AccessorIndex& accessor_index;

    template <DecoderConcept TKeyDecoder>
    segment::KVSegmentReader<TKeyDecoder, elias_fano::EliasFanoDecoder> kv_segment_reader() {
        return segment::KVSegmentReader<TKeyDecoder, elias_fano::EliasFanoDecoder>{kv_segment};
    }
};

}  // namespace silkworm::snapshots
