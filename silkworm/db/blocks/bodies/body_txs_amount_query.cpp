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
