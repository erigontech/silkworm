// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "txn_index.hpp"

#include <silkworm/db/blocks/bodies/body_txs_amount_query.hpp>
#include <silkworm/db/datastore/snapshots/segment/segment_reader.hpp>

#include "txn_segment_word_codec.hpp"

namespace silkworm::snapshots {

Bytes TransactionKeyFactory::make(ByteView key_data, uint64_t i) {
    return Bytes{tx_buffer_hash(key_data, first_tx_id_ + i)};
}

std::pair<uint64_t, uint64_t> TransactionIndex::compute_txs_amount(
    SnapshotPath bodies_segment_path,
    std::optional<MemoryMappedRegion> bodies_segment_region) {
    segment::SegmentFileReader body_segment{std::move(bodies_segment_path), bodies_segment_region};
    auto result = BodyTxsAmountSegmentQuery{body_segment}.exec();
    return {result.first_tx_id, result.count};
}

}  // namespace silkworm::snapshots
