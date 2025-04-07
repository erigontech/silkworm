// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "binary_search.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/assert.hpp>

namespace silkworm {

static void check_binary_find_if(const std::vector<int>& vec, const int value) {
    SILKWORM_ASSERT(std::ranges::is_sorted(vec));
    const auto res1{std::ranges::upper_bound(vec, value)};
    const auto res2{std::ranges::find_if(vec, [&](int x) { return x > value; })};
    CHECK(res1 == res2);
    const auto res3{binary_find_if(vec.size(), [&](size_t i) { return vec[i] > value; })};
    CHECK(std::cmp_equal(res1 - vec.begin(), res3));
}

TEST_CASE("binary_find_if") {
    check_binary_find_if({}, 42);
    check_binary_find_if({0}, -1);
    check_binary_find_if({0}, 0);
    check_binary_find_if({0}, 1);
    check_binary_find_if({1, 3, 3, 5}, 0);
    check_binary_find_if({1, 3, 3, 5}, 1);
    check_binary_find_if({1, 3, 3, 5}, 2);
    check_binary_find_if({1, 3, 3, 5}, 3);
    check_binary_find_if({1, 3, 3, 5}, 4);
    check_binary_find_if({1, 3, 3, 5}, 5);
    check_binary_find_if({1, 3, 3, 5}, 6);
}

}  // namespace silkworm
