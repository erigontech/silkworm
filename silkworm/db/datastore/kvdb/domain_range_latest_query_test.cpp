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

#include "domain_range_latest_query.hpp"

#include <functional>
#include <utility>

#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

#include "big_endian_codec.hpp"
#include "database.hpp"
#include "domain_put_latest_query.hpp"

namespace silkworm::datastore::kvdb {

template <std::ranges::input_range Range, typename Value = std::iter_value_t<std::ranges::iterator_t<Range>>>
std::vector<Value> vector_from_range(Range range) {
    std::vector<Value> results;
    std::ranges::copy(range, std::back_inserter(results));
    return results;
}

struct DomainPutEntry {
    uint64_t key{0};
    uint64_t value{0};
    Step step{0};
};

using DomainRangeQuery = DomainRangeLatestQuery<BigEndianU64Codec, BigEndianU64Codec, BigEndianU64Codec>;
using Result = std::vector<std::pair<uint64_t, uint64_t>>;

// by default has_large_values = false, is_multi_value = true
using DomainDefault = std::identity;

struct DomainWithLargeValues {
    Schema::DomainDef& operator()(Schema::DomainDef& domain) const {
        domain.enable_large_values().values_disable_multi_value();
        return domain;
    }
};

TEMPLATE_TEST_CASE("DomainRangeLatestQuery", "", DomainDefault, DomainWithLargeValues) {
    const TemporaryDirectory tmp_dir;
    ::mdbx::env_managed env = open_env(EnvConfig{.path = tmp_dir.path().string(), .create = true, .in_memory = true});

    EntityName name{"Test"};
    Schema::DatabaseDef schema;
    TestType domain_config;
    [[maybe_unused]] auto _ = domain_config(schema.domain(name));

    Database db{std::move(env), schema};
    db.create_tables();
    Domain entity = db.domain(name);
    RWAccess db_access = db.access_rw();

    auto find_in = [&db_access, &entity](const std::vector<DomainPutEntry>& data, uint64_t key_start, uint64_t key_end) -> Result {
        {
            RWTxnManaged tx = db_access.start_rw_tx();
            DomainPutLatestQuery<BigEndianU64Codec, BigEndianU64Codec> query{tx, entity};
            for (auto& entry : data) {
                query.exec(entry.key, entry.value, entry.step);
            }
            tx.commit_and_stop();
        }

        ROTxnManaged tx = db_access.start_ro_tx();
        DomainRangeQuery query{tx, entity};
        auto results = vector_from_range(query.exec(key_start, key_end, /* ascending = */ true));
        return results;
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
