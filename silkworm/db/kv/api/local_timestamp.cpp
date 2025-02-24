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

#include "local_timestamp.hpp"

#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::db::kv::api {

datastore::TimestampRange ts_range_from_kv(Timestamp from_ts, Timestamp to_ts, bool reverse) {
    // static_cast automatically handles conversion for all values included -1 => INF...
    datastore::TimestampRange range{static_cast<datastore::Timestamp>(reverse ? to_ts : from_ts),
                                    static_cast<datastore::Timestamp>(reverse ? from_ts : to_ts)};
    // ...but we still need to adjust some corner cases:
    // [-1, -1) means [StartOfTable, EndOfTable) i.e. [0, INF)
    // [from, -1) in reverse order means [StartOfTable, from) i.e. [0, from)
    if (to_ts == kInfinite && (from_ts == kInfinite || reverse)) {
        range.start = 0;
    }
    ensure(range.start <= range.end, [&]() { return "invalid forward range " + range.to_string(); });
    return range;
}

}  // namespace silkworm::db::kv::api
