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

#include "body_segment_collation.hpp"

#include <stdexcept>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/log.hpp>

#include "body_segment.hpp"

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;
using namespace datastore;

void BodySegmentCollation::copy(ROTxn& txn, const SegmentCollationCommand& command, snapshots::segment::SegmentFileWriter& file_writer) const {
    BlockNumRange range = command.range;
    uint64_t base_txn_id = command.base_txn_id;

    snapshots::BodySegmentWriter writer{file_writer};
    auto out = writer.out();
    for (BlockNum i = range.start; i < range.end; ++i) {
        auto value_opt = read_canonical_body_for_storage(txn, i);
        if (!value_opt) throw std::runtime_error{"BodySegmentCollation::copy missing body for block " + std::to_string(i)};
        BlockBodyForStorage& value = *value_opt;
        // remap to sequential values without gaps (see txnum.go)
        value.base_txn_id = base_txn_id;
        base_txn_id += value.txn_count;
        *out++ = value;
    }
}

void BodySegmentCollation::prune(RWTxn& txn, BlockNumRange range) const {
    for (BlockNum i = range.start, count = 1; i < range.end; ++i, ++count) {
        auto hash_opt = read_canonical_header_hash(txn, i);
        if (!hash_opt) continue;
        auto hash = *hash_opt;

        delete_body(txn, hash, i);

        if ((count > 10000) && ((count % 10000) == 0)) {
            SILK_DEBUG_M("BodySegmentCollation") << "cleaned up until block " << i;
        }
    }
}

}  // namespace silkworm::db
