// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "body_txs_amount_query.hpp"

#include <stdexcept>

#include "body_segment.hpp"

namespace silkworm::snapshots {

BodyTxsAmountSegmentQuery::Result BodyTxsAmountSegmentQuery::exec() {
    size_t body_count = segment_.item_count();
    if (body_count == 0) {
        throw std::runtime_error("BodyTxsAmountSegmentQuery empty body snapshot: " + segment_.path().path().string());
    }

    BodySegmentReader reader{segment_};
    auto it = reader.begin();
    uint64_t first_tx_id = it->base_txn_id;

    it += body_count - 1;
    auto& last_body = *it;

    uint64_t end_tx_id = last_body.base_txn_id + last_body.txn_count;
    uint64_t count = end_tx_id - first_tx_id;

    return Result{
        first_tx_id,
        count,
    };
}

}  // namespace silkworm::snapshots
