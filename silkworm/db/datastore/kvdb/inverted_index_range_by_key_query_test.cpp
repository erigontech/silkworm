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

#include "inverted_index_range_by_key_query.hpp"

#include <algorithm>
#include <iterator>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

#include "big_endian_codec.hpp"
#include "database.hpp"
#include "inverted_index_put_query.hpp"

namespace silkworm::datastore::kvdb {

std::vector<Timestamp> vector_from_range(auto range) {
    std::vector<Timestamp> results;
    std::ranges::copy(range, std::back_inserter(results));
    return results;
}

void init_inverted_index(RWTxn& tx, InvertedIndex ii, const std::multimap<uint64_t, Timestamp>& kvs) {
    InvertedIndexPutQuery<BigEndianU64Codec> put_query{tx, ii};
    for (auto& entry : kvs) {
        put_query.exec(entry.first, entry.second, true);
    }
}

TEST_CASE("InvertedIndexRangeByKeyQuery") {
    const TemporaryDirectory tmp_dir;
    ::mdbx::env_managed env = open_env(EnvConfig{.path = tmp_dir.path().string(), .create = true, .in_memory = true});

    EntityName name{"Test"};
    Schema::DatabaseDef schema;
    schema.inverted_index(name);

    Database db{std::move(env), schema};
    db.create_tables();
    InvertedIndex ii = db.inverted_index(name);
    RWAccess db_access = db.access_rw();

    auto find_in = [&db_access, &ii](const std::multimap<uint64_t, Timestamp>& kvs, uint64_t key, TimestampRange ts_range, bool ascending) -> std::vector<Timestamp> {
        {
            RWTxnManaged tx = db_access.start_rw_tx();
            init_inverted_index(tx, ii, kvs);
            tx.commit_and_stop();
        }

        ROTxnManaged tx = db_access.start_ro_tx();
        InvertedIndexRangeByKeyQuery<BigEndianU64Codec> query{tx, ii};
        return vector_from_range(query.exec(key, ts_range, ascending));
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
