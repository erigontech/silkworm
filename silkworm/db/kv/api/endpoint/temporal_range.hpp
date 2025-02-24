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

#pragma once

#include <string>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "common.hpp"
#include "paginated_sequence.hpp"

namespace silkworm::db::kv::api {

//! Unlimited range size in range queries
inline constexpr int64_t kUnlimited{-1};

//! Infinite timestamp value in range queries
inline constexpr Timestamp kInfinite{-1};

struct IndexRangeQuery {
    TxId tx_id{0};
    std::string table;
    Bytes key;
    Timestamp from_timestamp;
    Timestamp to_timestamp;
    bool ascending_order{false};
    int64_t limit{kUnlimited};
    uint32_t page_size{0};
    std::string page_token;
};

struct IndexRangeResult {
    ListOfTimestamp timestamps;
    std::string next_page_token;
};

struct RangeResult {
    ListOfBytes keys;
    ListOfBytes values;
    std::string next_page_token;
};

struct HistoryRangeQuery {
    TxId tx_id{0};
    std::string table;
    Timestamp from_timestamp;
    Timestamp to_timestamp;
    bool ascending_order{false};
    int64_t limit{kUnlimited};
    uint32_t page_size{0};
    std::string page_token;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const HistoryRangeQuery&) const = default;
};

inline bool operator==(const HistoryRangeQuery& lhs, const HistoryRangeQuery& rhs) {
    return (lhs.tx_id == rhs.tx_id) &&
           (lhs.table == rhs.table) &&
           (lhs.from_timestamp == rhs.from_timestamp) &&
           (lhs.to_timestamp == rhs.to_timestamp) &&
           (lhs.ascending_order == rhs.ascending_order) &&
           (lhs.limit == rhs.limit) &&
           (lhs.page_size == rhs.page_size) &&
           (lhs.page_token == rhs.page_token);
}

using HistoryRangeResult = RangeResult;

struct DomainRangeQuery {
    TxId tx_id{0};
    std::string table;
    Bytes from_key;
    Bytes to_key;
    std::optional<Timestamp> timestamp;  // not present means 'latest state' (no history lookup)
    bool ascending_order{false};
    int64_t limit{kUnlimited};
    uint32_t page_size{0};
    std::string page_token;
};

using DomainRangeResult = RangeResult;

using PaginatedTimestamps = PaginatedSequence<Timestamp>;
using PaginatedKeysValues = PaginatedSequencePair<Bytes, Bytes>;

}  // namespace silkworm::db::kv::api
