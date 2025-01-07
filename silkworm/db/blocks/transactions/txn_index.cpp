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
