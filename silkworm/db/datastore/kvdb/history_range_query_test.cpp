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

#include "history_range_query.hpp"

#include <functional>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

#include "../common/ranges/vector_from_range.hpp"
#include "big_endian_codec.hpp"
#include "database.hpp"
#include "history_put_query.hpp"

namespace silkworm::datastore::kvdb {

struct HistoryPutEntry {
    uint64_t key{0};
    uint64_t value{0};
    Timestamp timestamp{0};
};
using Entry = HistoryPutEntry;

using Result = std::vector<std::pair<uint64_t, uint64_t>>;

// by default has_large_values = false, is_multi_value = true
using DomainDefault = std::identity;

struct DomainWithLargeValues {
    Schema::DomainDef& operator()(Schema::DomainDef& domain) const {
        domain.enable_large_values().values_disable_multi_value();
        return domain;
    }
};

TEMPLATE_TEST_CASE("HistoryRangeQuery", "", DomainDefault, DomainWithLargeValues) {
    const TemporaryDirectory tmp_dir;
    ::mdbx::env_managed env = open_env(EnvConfig{.path = tmp_dir.path().string(), .create = true, .in_memory = true});

    EntityName name{"Test"};
    Schema::DatabaseDef schema;
    TestType domain_config;
    [[maybe_unused]] auto _ = domain_config(schema.domain(name));

    Database db{std::move(env), schema};
    db.create_tables();
    Domain domain = db.domain(name);
    History& entity = *domain.history;
    RWAccess db_access = db.access_rw();

    auto find_in = [&db_access, &entity](const std::vector<Entry>& data, TimestampRange ts_range) -> Result {
        {
            RWTxnManaged tx = db_access.start_rw_tx();
            HistoryPutQuery<BigEndianU64Codec, BigEndianU64Codec> query{tx, entity};
            for (auto& entry : data) {
                query.exec(entry.key, entry.value, entry.timestamp);
            }
            tx.commit_and_stop();
        }

        ROTxnManaged tx = db_access.start_ro_tx();
        HistoryRangeQuery<BigEndianU64Codec, BigEndianU64Codec> query{tx, entity};
        return vector_from_range(query.exec(ts_range, true));
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
