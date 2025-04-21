// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

#include <silkworm/core/common/bytes.hpp>

#include "common.hpp"
#include "sequence.hpp"

namespace silkworm::db::kv::api {

//! Unlimited range size in range queries
inline constexpr int64_t kUnlimited{-1};

//! Infinite timestamp value in range queries
inline constexpr Timestamp kInfinite{-1};

struct IndexRangeRequest {
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

struct HistoryRangeRequest {
    TxId tx_id{0};
    std::string table;
    Timestamp from_timestamp;
    Timestamp to_timestamp;
    bool ascending_order{false};
    int64_t limit{kUnlimited};
    uint32_t page_size{0};
    std::string page_token;

    // TODO(canepat) we need clang >= 17 to use spaceship operator instead of hand-made operator== below
    // auto operator<=>(const HistoryRangeRequest&) const = default;
};

inline bool operator==(const HistoryRangeRequest& lhs, const HistoryRangeRequest& rhs) {
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

struct DomainRangeRequest {
    TxId tx_id{0};
    std::string table;
    Bytes from_key;
    Bytes to_key;
    std::optional<Timestamp> timestamp;  // not present means 'latest state' (no history lookup)
    bool ascending_order{false};
    int64_t limit{kUnlimited};
    uint32_t page_size{0};
    std::string page_token;
    bool skip_empty_values{false};
};

using DomainRangeResult = RangeResult;

using RawKeyValue = std::pair<Bytes, Bytes>;

using TimestampStream = Stream<Timestamp>;
using KeyValueStream = Stream<RawKeyValue>;

using TimestampStreamFactory = StreamFactory<Timestamp>;
using KeyValueStreamFactory = StreamFactory<RawKeyValue>;

using TimestampStreamReply = StreamReply<Timestamp>;
using KeyValueStreamReply = StreamReply<RawKeyValue>;

}  // namespace silkworm::db::kv::api
