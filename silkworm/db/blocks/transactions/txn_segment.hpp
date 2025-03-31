// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_writer.hpp>

#include "txn_segment_word_codec.hpp"

namespace silkworm::snapshots {

using TransactionSegmentReader = segment::SegmentReader<TransactionSegmentWordDecoder>;
using TransactionSegmentWriter = segment::SegmentWriter<TransactionSegmentWordEncoder>;

template <BytesOrByteViewConcept TBytes>
using TransactionSegmentPayloadRlpReader = segment::SegmentReader<TransactionSegmentWordPayloadRlpDecoder<TBytes>>;

}  // namespace silkworm::snapshots
