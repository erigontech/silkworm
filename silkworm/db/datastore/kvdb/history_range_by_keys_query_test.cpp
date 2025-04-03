// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "history_range_by_keys_query.hpp"

#include <utility>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include "big_endian_codec.hpp"
#include "history_put_query.hpp"
#include "query_test.hpp"

namespace silkworm::datastore::kvdb {

struct Entry {
    uint64_t key{0};
    uint64_t value{0};
    Timestamp timestamp{0};
};

using HistoryRangeQuery = HistoryRangeByKeysQuery<BigEndianU64Codec, BigEndianU64Codec, BigEndianU64Codec>;
using Result = std::vector<std::pair<uint64_t, uint64_t>>;

TEMPLATE_TEST_CASE("HistoryRangeByKeysQuery", "", DomainDefault, DomainWithLargeValues) {
    QueryTest test = QueryTest::make<TestType>();

    auto find_in = [&test](const std::vector<Entry>& data, uint64_t key_start, uint64_t key_end, Timestamp timestamp) -> Result {
        return test.find_in<EntityKind::kHistory, Entry, HistoryPutQuery<BigEndianU64Codec, BigEndianU64Codec>, HistoryRangeQuery>(data, key_start, key_end, timestamp, /* ascending = */ true);
    };

    SECTION("single entry - correct key") {
        CHECK(find_in({Entry{1, 2, 3}}, 1, 2, 3) == Result{{1, 2}});
    }
    SECTION("single entry - wrong key") {
        CHECK(find_in({Entry{1, 2, 3}}, 4, 5, 3).empty());
    }
    SECTION("same timestamp - different keys") {
        CHECK(find_in({Entry{1, 11, 100}, Entry{2, 22, 100}, Entry{3, 33, 100}}, 2, 3, 100) == Result{{2, 22}});
    }
    SECTION("different timestamps - different keys") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{2, 22, 102}, Entry{3, 33, 103}}, 2, 3, 100) == Result{{2, 22}});
    }
    SECTION("different timestamps - same key") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{1, 22, 102}, Entry{1, 33, 103}}, 1, 2, 100) == Result{{1, 11}});
    }
    SECTION("find keys [1..3] in [2..5]") {
        CHECK(find_in({Entry{2, 22, 100}, Entry{3, 33, 100}, Entry{4, 44, 100}, Entry{5, 55, 100}}, 1, 4, 100) == Result{{2, 22}, {3, 33}});
    }
    SECTION("find keys [4..6] in [2..5]") {
        CHECK(find_in({Entry{2, 22, 100}, Entry{3, 33, 100}, Entry{4, 44, 100}, Entry{5, 55, 100}}, 4, 7, 100) == Result{{4, 44}, {5, 55}});
    }
    SECTION("find all") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, 0, 100, 0) == Result{{11, 111}, {22, 222}, {33, 333}});
    }
    SECTION("find all in unsorted") {
        CHECK(find_in({Entry{33, 333, 3}, Entry{22, 222, 2}, Entry{11, 111, 1}}, 0, 100, 0) == Result{{11, 111}, {22, 222}, {33, 333}});
    }
    SECTION("find from timestamp") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, 0, 100, 2) == Result{{22, 222}, {33, 333}});
    }
    SECTION("find none given non-overlapping ts range") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{22, 222, 2}, Entry{33, 333, 3}}, 0, 100, 10).empty());
    }
    SECTION("find none in empty") {
        CHECK(find_in({}, 0, 100, 0).empty());
    }
    SECTION("find all - with duplicates") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{11, 112, 2}, Entry{22, 222, 3}, Entry{22, 223, 4}}, 0, 100, 0) == Result{{11, 111}, {22, 222}});
    }
    SECTION("find all in unsorted - with duplicates") {
        CHECK(find_in({Entry{22, 223, 4}, Entry{22, 222, 3}, Entry{11, 112, 2}, Entry{11, 111, 1}}, 0, 100, 0) == Result{{11, 111}, {22, 222}});
    }
    SECTION("find from timestamp - with duplicates") {
        CHECK(find_in({Entry{11, 111, 1}, Entry{11, 112, 2}, Entry{22, 222, 3}, Entry{22, 223, 4}}, 0, 100, 2) == Result{{11, 112}, {22, 222}});
    }
}

}  // namespace silkworm::datastore::kvdb
