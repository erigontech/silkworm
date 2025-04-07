// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "history_range_in_period_query.hpp"

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include "big_endian_codec.hpp"
#include "history_put_query.hpp"
#include "query_test.hpp"

namespace silkworm::datastore::kvdb {

struct HistoryPutEntry {
    uint64_t key{0};
    uint64_t value{0};
    Timestamp timestamp{0};
};
using Entry = HistoryPutEntry;

using HistoryRangeQuery = HistoryRangeInPeriodQuery<BigEndianU64Codec, BigEndianU64Codec>;
using Result = std::vector<std::pair<uint64_t, uint64_t>>;

TEMPLATE_TEST_CASE("HistoryRangeInPeriodQuery", "", DomainDefault, DomainWithLargeValues) {
    QueryTest test = QueryTest::make<TestType>();

    auto find_in = [&test](const std::vector<Entry>& data, TimestampRange ts_range) -> Result {
        return test.find_in<EntityKind::kHistory, Entry, HistoryPutQuery<BigEndianU64Codec, BigEndianU64Codec>, HistoryRangeQuery>(data, ts_range, /* ascending = */ true);
    };

    SECTION("find all") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, {0, 10}) == Result{{11, 111}, {22, 222}, {33, 333}});
    }
    SECTION("find all in unsorted") {
        CHECK(find_in({Entry{33, 333, 3}, Entry{22, 222, 2}, Entry{11, 111, 1}}, {0, 10}) == Result{{11, 111}, {22, 222}, {33, 333}});
    }
    SECTION("find from timestamp") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, {2, 10}) == Result{{22, 222}, {33, 333}});
    }
    SECTION("find before timestamp") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, {0, 3}) == Result{{11, 111}, {22, 222}});
    }
    SECTION("find none given non-overlapping ts range") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, {10, 20}).empty());
    }
    SECTION("find none in empty") {
        CHECK(find_in({}, {0, 10}).empty());
    }
    SECTION("find all - with duplicates") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{11, 112, 2}, Entry{22, 222, 3}, Entry{22, 223, 4}}, {0, 10}) == Result{{11, 111}, {22, 222}});
    }
    SECTION("find all in unsorted - with duplicates") {
        CHECK(find_in({Entry{22, 223, 4}, Entry{22, 222, 3}, Entry{11, 112, 2}, Entry{11, 111, 1}}, {0, 10}) == Result{{11, 111}, {22, 222}});
    }
    SECTION("find from timestamp - with duplicates") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{11, 112, 2}, Entry{22, 222, 3}, Entry{22, 223, 4}}, {2, 10}) == Result{{11, 112}, {22, 222}});
    }
}

}  // namespace silkworm::datastore::kvdb
