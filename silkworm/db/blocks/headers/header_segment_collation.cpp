// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "header_segment_collation.hpp"

#include <stdexcept>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/log.hpp>

#include "header_segment.hpp"

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;
using namespace datastore;

void HeaderSegmentCollation::copy(ROTxn& txn, const SegmentCollationCommand& command, snapshots::segment::SegmentFileWriter& file_writer) const {
    BlockNumRange range = command.range;
    snapshots::HeaderSegmentWriter writer{file_writer};
    auto out = writer.out();
    for (BlockNum i = range.start; i < range.end; ++i) {
        auto value_opt = read_canonical_header(txn, i);
        if (!value_opt) throw std::runtime_error{"HeaderSegmentCollation::copy missing header for block " + std::to_string(i)};
        *out++ = *value_opt;
    }
}

void HeaderSegmentCollation::prune(RWTxn& txn, BlockNumRange range) const {
    for (BlockNum i = range.start, count = 1; i < range.end; ++i, ++count) {
        auto hash_opt = read_canonical_header_hash(txn, i);
        if (!hash_opt) continue;
        auto& hash = *hash_opt;

        delete_header(txn, i, hash);

        if ((count > 10000) && ((count % 10000) == 0)) {
            SILK_DEBUG_M("HeaderSegmentCollation") << "cleaned up until block " << i;
        }
    }
}

}  // namespace silkworm::db
