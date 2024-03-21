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

#include "snapshot.hpp"
#include "txn_hash.hpp"

namespace silkworm::snapshots {

Bytes TransactionKeyFactory::make(ByteView key_data, uint64_t i) {
    return Bytes{tx_buffer_hash(key_data, first_tx_id_ + i)};
}

SnapshotPath TransactionIndex::bodies_segment_path(const SnapshotPath& segment_path) {
    return SnapshotPath::from(
        segment_path.path().parent_path(),
        segment_path.version(),
        segment_path.block_from(),
        segment_path.block_to(),
        SnapshotType::bodies);
}

std::pair<uint64_t, uint64_t> TransactionIndex::compute_txs_amount(const SnapshotPath& bodies_segment_path) {
    BodySnapshot bodies_snapshot{bodies_segment_path};
    bodies_snapshot.reopen_segment();
    return bodies_snapshot.compute_txs_amount();
}

}  // namespace silkworm::snapshots
