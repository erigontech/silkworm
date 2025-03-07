/*
   Copyright 2025 The Silkworm Authors

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

#include "history_get_query.hpp"

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

using Result = tl::expected<uint64_t, HistoryGetQuery<BigEndianU64Codec, BigEndianU64Codec>::NoValueReason>;

TEMPLATE_TEST_CASE("HistoryGetQuery", "", DomainDefault, DomainWithLargeValues) {
    QueryTest test = QueryTest::make<TestType>();

    auto find_in = [&test](const std::vector<Entry>& data, uint64_t key, Timestamp timestamp) -> Result {
        return test.find_in<EntityKind::kHistory, Entry, HistoryPutQuery<BigEndianU64Codec, BigEndianU64Codec>, HistoryGetQuery<BigEndianU64Codec, BigEndianU64Codec>>(data, key, timestamp);
    };

    SECTION("single entry - correct key") {
        CHECK(find_in({Entry{1, 2, 3}}, 1, 3) == 2);
    }
    SECTION("single entry - wrong key") {
        CHECK_FALSE(find_in({Entry{1, 2, 3}}, 4, 3).has_value());
    }
    SECTION("different timestamps - different keys") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{2, 22, 102}, Entry{3, 33, 103}}, 2, 102) == 22);
    }
    SECTION("same timestamp - different keys") {
        CHECK(find_in({Entry{1, 11, 100}, Entry{2, 22, 100}, Entry{3, 33, 100}}, 2, 100) == 22);
    }
    SECTION("ascending timestamps - same key - before first") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{1, 33, 103}}, 1, 100) == 11);
    }
    SECTION("ascending timestamps - same key - first") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{1, 33, 103}}, 1, 101) == 11);
    }
    SECTION("ascending timestamps - same key - gap") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{1, 33, 103}}, 1, 102) == 33);
    }
    SECTION("ascending timestamps - same key - last") {
        CHECK(find_in({Entry{1, 11, 101}, Entry{1, 33, 103}}, 1, 103) == 33);
    }
    SECTION("ascending timestamps - same key - after last") {
        CHECK_FALSE(find_in({Entry{1, 11, 101}, Entry{1, 33, 103}}, 1, 104).has_value());
    }
    SECTION("descending timestamps - same key - before first") {
        CHECK(find_in({Entry{1, 33, 103}, Entry{1, 11, 101}}, 1, 100) == 11);
    }
    SECTION("descending timestamps - same key - first") {
        CHECK(find_in({Entry{1, 33, 103}, Entry{1, 11, 101}}, 1, 101) == 11);
    }
    SECTION("descending timestamps - same key - gap") {
        CHECK(find_in({Entry{1, 33, 103}, Entry{1, 11, 101}}, 1, 102) == 33);
    }
    SECTION("descending timestamps - same key - last") {
        CHECK(find_in({Entry{1, 33, 103}, Entry{1, 11, 101}}, 1, 103) == 33);
    }
    SECTION("descending timestamps - same key - after last") {
        CHECK_FALSE(find_in({Entry{1, 33, 103}, Entry{1, 11, 101}}, 1, 104).has_value());
    }
}

}  // namespace silkworm::datastore::kvdb
