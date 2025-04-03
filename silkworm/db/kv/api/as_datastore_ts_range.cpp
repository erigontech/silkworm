// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "as_datastore_ts_range.hpp"

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::db::kv::api {

datastore::TimestampRange as_datastore_ts_range(TimestampRange ts_range, bool reverse) {
    const auto [from_ts, to_ts] = ts_range;

    // static_cast automatically handles conversion for all values included -1 => INF...
    datastore::TimestampRange db_range{static_cast<datastore::Timestamp>(reverse ? to_ts : from_ts),
                                       static_cast<datastore::Timestamp>(reverse ? from_ts : to_ts)};
    // ...but we still need to adjust some corner cases:
    // [-1, -1) means [StartOfTable, EndOfTable) i.e. [0, INF)
    // [from, -1) in reverse order means [StartOfTable, from) i.e. [0, from)
    if (to_ts == kInfinite && (from_ts == kInfinite || reverse)) {
        db_range.start = 0;
    }
    ensure(db_range.start <= db_range.end, [&]() { return "invalid forward range " + db_range.to_string(); });
    return db_range;
}

}  // namespace silkworm::db::kv::api
