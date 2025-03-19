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

#include "domain_get_latest_query.hpp"

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

using DomainGetQuery = DomainGetLatestQuery<BigEndianU64Codec, BigEndianU64Codec>;
using Result = DomainGetQuery::Result;

bool operator==(const Result& lhs, const Result& rhs) {
    return (lhs.value == rhs.value) && (lhs.step == rhs.step);
};

TEMPLATE_TEST_CASE("DomainGetLatestQuery", "", DomainDefault, DomainWithLargeValues) {
    QueryTest test = QueryTest::make<TestType>();

    auto find_in = [&test](const std::vector<DomainPutEntry>& data, uint64_t key) -> std::optional<Result> {
        return test.find_in<EntityKind::kDomain, DomainPutEntry, DomainPutLatestQuery<BigEndianU64Codec, BigEndianU64Codec>, DomainGetQuery>(data, key);
    };

    auto count = [&test]() -> uint64_t {
        Domain entity = test.domain();
        RWAccess db_access = test.access_rw();

        ROTxnManaged tx = db_access.start_ro_tx();
        PooledCursor cursor{tx, entity.values_table};
        return cursor.get_map_stat().ms_entries;
    };

    SECTION("single entry - correct key") {
        CHECK(find_in({DomainPutEntry{1, 2, Step{3}}}, 1) == Result{2, Step{3}});
        CHECK(count() == 1);
    }
    SECTION("single entry - wrong key") {
        CHECK_FALSE(find_in({DomainPutEntry{1, 2, Step{3}}}, 4).has_value());
        CHECK(count() == 1);
    }
    SECTION("different steps - different keys") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{101}}, DomainPutEntry{2, 22, Step{102}}, DomainPutEntry{3, 33, Step{103}}}, 2) == Result{22, Step{102}});
        CHECK(count() == 3);
    }
    SECTION("ascending steps - same key") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{101}}, DomainPutEntry{1, 22, Step{102}}, DomainPutEntry{1, 33, Step{103}}}, 1) == Result{33, Step{103}});
        CHECK(count() == 3);
    }
    SECTION("descending steps - same key") {
        CHECK(find_in({DomainPutEntry{1, 33, Step{103}}, DomainPutEntry{1, 22, Step{102}}, DomainPutEntry{1, 11, Step{101}}}, 1) == Result{33, Step{103}});
        CHECK(count() == 3);
    }
    SECTION("same step - different key") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{100}}, DomainPutEntry{2, 22, Step{100}}, DomainPutEntry{3, 33, Step{100}}}, 2) == Result{22, Step{100}});
        CHECK(count() == 3);
    }
    SECTION("same step - same key") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{100}}, DomainPutEntry{1, 22, Step{100}}, DomainPutEntry{1, 33, Step{100}}}, 1) == Result{33, Step{100}});
        CHECK(count() == 1);
    }
    SECTION("ascending and same steps - same key") {
        CHECK(find_in({DomainPutEntry{1, 11, Step{101}}, DomainPutEntry{1, 22, Step{102}}, DomainPutEntry{1, 33, Step{103}}, DomainPutEntry{1, 331, Step{103}}}, 1) == Result{331, Step{103}});
        CHECK(count() == 3);
    }
    SECTION("descending and same steps - same key") {
        CHECK(find_in({DomainPutEntry{1, 33, Step{103}}, DomainPutEntry{1, 331, Step{103}}, DomainPutEntry{1, 22, Step{102}}, DomainPutEntry{1, 11, Step{101}}}, 1) == Result{331, Step{103}});
        CHECK(count() == 3);
    }
}

}  // namespace silkworm::datastore::kvdb
