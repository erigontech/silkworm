// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inverted_index_range_by_key_query.hpp"

#include <map>

#include <catch2/catch_test_macros.hpp>

#include "big_endian_codec.hpp"
#include "inverted_index_put_query.hpp"
#include "query_test.hpp"

namespace silkworm::datastore::kvdb {

struct Entry {
    uint64_t key{0};
    Timestamp timestamp{0};
    bool with_index_update{true};
};

TEST_CASE("InvertedIndexRangeByKeyQuery") {
    QueryTest test = QueryTest::make<DomainDefault>();

    auto find_in = [&test](const std::vector<Entry>& data, uint64_t key, TimestampRange ts_range, bool ascending) -> std::vector<Timestamp> {
        return test.find_in<EntityKind::kInvertedIndex, Entry, InvertedIndexPutQuery<BigEndianU64Codec>, InvertedIndexRangeByKeyQuery<BigEndianU64Codec>>(data, key, ts_range, ascending);
    };

    SECTION("asc - all") {
        CHECK(find_in({{1, 1}, {1, 2}, {1, 3}}, 1, TimestampRange{0, 10}, true) == std::vector<Timestamp>{1, 2, 3});
    }
    SECTION("asc - all with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 2}, {1, 3}, {2, 2}}, 1, TimestampRange{0, 10}, true) == std::vector<Timestamp>{1, 2, 3});
    }
    SECTION("asc - middle") {
        CHECK(find_in({{1, 1}, {1, 2}, {1, 3}}, 1, TimestampRange{2, 3}, true) == std::vector<Timestamp>{2});
    }
    SECTION("asc - middle gap") {
        CHECK(find_in({{1, 1}, {1, 3}}, 1, TimestampRange{2, 3}, true).empty());
    }
    SECTION("asc - middle to end with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 2}, {1, 3}, {2, 2}}, 1, TimestampRange{2, 10}, true) == std::vector<Timestamp>{2, 3});
    }
    SECTION("asc - middle gap to end with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 3}, {2, 2}}, 1, TimestampRange{2, 10}, true) == std::vector<Timestamp>{3});
    }
    SECTION("desc - all") {
        CHECK(find_in({{1, 1}, {1, 2}, {1, 3}}, 1, TimestampRange{0, 10}, false) == std::vector<Timestamp>{3, 2, 1});
    }
    SECTION("desc - all with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 2}, {1, 3}, {2, 2}}, 1, TimestampRange{0, 10}, false) == std::vector<Timestamp>{3, 2, 1});
    }
    SECTION("desc - middle") {
        CHECK(find_in({{1, 1}, {1, 2}, {1, 3}}, 1, TimestampRange{2, 3}, false) == std::vector<Timestamp>{2});
    }
    SECTION("desc - middle gap") {
        CHECK(find_in({{1, 1}, {1, 3}}, 1, TimestampRange{2, 3}, false).empty());
    }
    SECTION("desc - middle to start with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 2}, {1, 3}, {2, 2}}, 1, TimestampRange{0, 3}, false) == std::vector<Timestamp>{2, 1});
    }
    SECTION("desc - middle gap to start with neighbor keys") {
        CHECK(find_in({{0, 2}, {1, 1}, {1, 3}, {2, 2}}, 1, TimestampRange{0, 3}, false) == std::vector<Timestamp>{1});
    }
}

}  // namespace silkworm::datastore::kvdb
