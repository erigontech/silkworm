// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "concat_view.hpp"

#include <catch2/catch_test_macros.hpp>

#include "owning_view.hpp"
#include "vector_from_range.hpp"

namespace silkworm::views {

static_assert(std::ranges::input_range<ConcatView<std::vector<int>, std::vector<int>>>);
static_assert(std::ranges::view<ConcatView<std::vector<int>, std::vector<int>>>);

TEST_CASE("ConcatView") {
    CHECK(vector_from_range(concat(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}),
              silkworm::ranges::owning_view(std::vector<int>{4, 5, 6}))) == std::vector<int>{1, 2, 3, 4, 5, 6});

    auto even = [](int x) { return x % 2 == 0; };
    auto odd = [](int x) { return x % 2 == 1; };
    CHECK(vector_from_range(concat(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(even),
              silkworm::ranges::owning_view(std::vector<int>{4, 5, 6}) | std::views::filter(odd))) == std::vector<int>{2, 5});
    CHECK(vector_from_range(concat(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(odd),
              silkworm::ranges::owning_view(std::vector<int>{4, 5, 6}) | std::views::filter(even))) == std::vector<int>{1, 3, 4, 6});

    CHECK(vector_from_range(concat(std::ranges::empty_view<int>{}, std::ranges::empty_view<int>{})).empty());
    CHECK(vector_from_range(concat(silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}), std::ranges::empty_view<int>{})) == std::vector<int>{1, 2, 3});
    CHECK(vector_from_range(concat(std::ranges::empty_view<int>{}, silkworm::ranges::owning_view(std::vector<int>{4, 5, 6}))) == std::vector<int>{4, 5, 6});

    CHECK(vector_from_range(concat(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::transform([](int v) { return std::vector<int>{v, v, v}; }) | std::views::join,
              silkworm::ranges::owning_view(std::vector<int>{4, 4, 4}))) == std::vector<int>{1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4});
}

}  // namespace silkworm::views
