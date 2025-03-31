// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "util.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::datastore::etl {

TEST_CASE("ETL Entry comparison") {
    Entry a{*from_hex("1a"), *from_hex("75")};
    Entry b{*from_hex("f7"), *from_hex("4056")};
    CHECK(a < b);
    CHECK(!(b < a));
    CHECK(!(a < a));
    CHECK(!(b < b));

    Entry c{*from_hex("ee48"), *from_hex("75")};
    Entry d{*from_hex("ee48"), *from_hex("4056")};
    CHECK(!(c < d));
    CHECK(d < c);
    CHECK(!(c < c));
    CHECK(!(d < d));
}

}  // namespace silkworm::datastore::etl
