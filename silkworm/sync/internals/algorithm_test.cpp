// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "algorithm.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("move_at_end on vectors") {
    std::vector<int> source = {4, 5, 6};
    std::vector<int> destination = {1, 2, 3};

    move_at_end(destination, source);
    REQUIRE(source.size() == 3);  // source has elements but moved
    REQUIRE(destination.size() == 6);
    REQUIRE(destination == std::vector({1, 2, 3, 4, 5, 6}));
}

TEST_CASE("push_all on vectors") {
    std::vector<int> source = {4, 5, 6};
    std::stack<int> destination({1, 2, 3});

    push_all(destination, source);
    REQUIRE(source.size() == 3);
    REQUIRE(destination.size() == 6);
    REQUIRE(destination == std::stack<int>({1, 2, 3, 4, 5, 6}));
}

}  // namespace silkworm
