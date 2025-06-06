// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "as_datastore_ts_range.hpp"

#include <optional>
#include <tuple>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/test_util/fixture.hpp>

namespace silkworm::db::kv::api {

using namespace silkworm::test_util;

TEST_CASE("ts_range_from_kv", "[db][kv][api][local_timestamp]") {
    const Fixtures<std::pair<TimestampRange, bool>, std::optional<datastore::TimestampRange>> test_fixtures{
        /* ascending order */
        {{{0, 20}, /*reverse=*/false}, datastore::TimestampRange{0, 20}},
        {{{10, 20}, /*reverse=*/false}, datastore::TimestampRange{10, 20}},
        {{{10, -1}, /*reverse=*/false}, datastore::TimestampRange{10, datastore::kMaxTimestamp}},
        {{{-1, -1}, /*reverse=*/false}, datastore::TimestampRange{0, datastore::kMaxTimestamp}},

        {{{20, 0}, /*reverse=*/false}, std::nullopt},
        {{{20, 10}, /*reverse=*/false}, std::nullopt},
        {{{-1, 10}, /*reverse=*/false}, std::nullopt},

        /* descending order */
        {{{20, 0}, /*reverse=*/true}, datastore::TimestampRange{0, 20}},
        {{{20, 10}, /*reverse=*/true}, datastore::TimestampRange{10, 20}},
        {{{-1, 10}, /*reverse=*/true}, datastore::TimestampRange{10, datastore::kMaxTimestamp}},
        {{{-1, -1}, /*reverse=*/true}, datastore::TimestampRange{0, datastore::kMaxTimestamp}},

        {{{0, 20}, /*reverse=*/true}, std::nullopt},
        {{{10, 20}, /*reverse=*/true}, std::nullopt},
    };

    for (const auto& [kv_ts_range_and_reverse, expected_db_ts_range] : test_fixtures) {
        const auto& [kv_ts_range, reverse] = kv_ts_range_and_reverse;
        const auto convert_ts_range_from_kv = [&]() {
            return as_datastore_ts_range({kv_ts_range.first, kv_ts_range.second}, reverse);
        };
        if (expected_db_ts_range) {
            const auto db_ts_range = convert_ts_range_from_kv();
            CHECK(db_ts_range.start == expected_db_ts_range->start);
            CHECK(db_ts_range.end == expected_db_ts_range->end);
        } else {
            CHECK_THROWS(convert_ts_range_from_kv());
        }
    }
}

}  // namespace silkworm::db::kv::api
