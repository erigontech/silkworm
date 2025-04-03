// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "random_number.hpp"

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("random numbers") {
    uint64_t a = 0;
    uint64_t b = 3;
    RandomNumber random_number(a, b);

    for (int i = 0; i < 100; ++i) {
        auto a_number = random_number.generate_one();
        REQUIRE((a <= a_number && a_number <= b));
    }
}

}  // namespace silkworm
