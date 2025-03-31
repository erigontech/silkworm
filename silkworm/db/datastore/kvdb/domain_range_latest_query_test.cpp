// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "domain_range_latest_query.hpp"

#include <utility>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include "big_endian_codec.hpp"
#include "domain_put_latest_query.hpp"
#include "query_test.hpp"

namespace silkworm::datastore::kvdb {

struct DomainPutEntry {
    uint64_t key{0};
    uint64_t value{0};
    Step step{0};
};

using DomainRangeQuery = DomainRangeLatestQuery<BigEndianU64Codec, BigEndianU64Codec, BigEndianU64Codec>;
using Result = std::vector<std::pair<uint64_t, uint64_t>>;

TEMPLATE_TEST_CASE("DomainRangeLatestQuery", "", DomainDefault, DomainWithLargeValues) {
    QueryTest test = QueryTest::make<TestType>();

    auto find_in = [&test](const std::vector<DomainPutEntry>& data, uint64_t key_start, uint64_t key_end) -> Result {
        return test.find_in<EntityKind::kDomain, DomainPutEntry, DomainPutLatestQuery<BigEndianU64Codec, BigEndianU64Codec>, DomainRangeQuery>(data, key_start, key_end, /* ascending = */ true);
    };

    SECTION("single entry - correct key") {
        CHECK(find_in({DomainPutEntry{1, 2, Step{3}}}, 1, 2) == Result{{1, 2}});
    }
    SECTION("single entry - wrong key") {
        CHECK(find_in({DomainPutEntry{1, 2, Step{3}}}, 4, 5).empty());
    }
    SECTION("same step - different keys") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{100}}, DomainPutEntry{2, 22, Step{100}}, DomainPutEntry{3, 33, Step{100}}}, 2, 3) == Result{{2, 22}});
    }
    SECTION("different steps - different keys") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{101}}, DomainPutEntry{2, 22, Step{102}}, DomainPutEntry{3, 33, Step{103}}}, 2, 3) == Result{{2, 22}});
    }
    SECTION("different steps - same key") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{101}}, DomainPutEntry{1, 22, Step{102}}, DomainPutEntry{1, 33, Step{103}}}, 1, 2) == Result{{1, 33}});
    }
    SECTION("find [1..3] in [2..5]") {
        CHECK(find_in({DomainPutEntry{2, 22, Step{100}}, DomainPutEntry{3, 33, Step{100}}, DomainPutEntry{4, 44, Step{100}}, DomainPutEntry{5, 55, Step{100}}}, 1, 4) == Result{{2, 22}, {3, 33}});
    }
    SECTION("find [4..6] in [2..5]") {
        CHECK(find_in({DomainPutEntry{2, 22, Step{100}}, DomainPutEntry{3, 33, Step{100}}, DomainPutEntry{4, 44, Step{100}}, DomainPutEntry{5, 55, Step{100}}}, 4, 7) == Result{{4, 44}, {5, 55}});
    }
}

}  // namespace silkworm::datastore::kvdb
