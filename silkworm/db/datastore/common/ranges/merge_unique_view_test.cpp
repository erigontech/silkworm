// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "merge_unique_view.hpp"

#include <string>

#include <catch2/catch_test_macros.hpp>

#include "owning_view.hpp"
#include "vector_from_range.hpp"

namespace silkworm::views {

static_assert(std::ranges::input_range<MergeUniqueView<std::vector<int>, std::vector<int>>>);
static_assert(std::ranges::view<MergeUniqueView<std::vector<int>, std::vector<int>>>);

TEST_CASE("MergeUniqueView") {
    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}))) ==
          std::vector<int>{1, 2, 3, 4});

    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3, 4, 5}),
              silkworm::ranges::owning_view(std::vector<int>{3, 4, 5, 6, 7}))) ==
          std::vector<int>{1, 2, 3, 4, 5, 6, 7});

    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3, 4, 5, 5, 5}),
              silkworm::ranges::owning_view(std::vector<int>{3, 4, 5, 6, 7}))) ==
          std::vector<int>{1, 2, 3, 4, 5, 6, 7});

    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{0, 2, 2, 2, 4, 5, 6, 6, 7, 7}),
              silkworm::ranges::owning_view(std::vector<int>{0, 0, 1, 2, 3, 5, 5, 6, 8, 9}))) ==
          std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9});

    auto even = [](int x) { return x % 2 == 0; };
    auto odd = [](int x) { return x % 2 == 1; };
    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(even),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}) | std::views::filter(odd))) ==
          std::vector<int>{2, 3});
    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(odd),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}) | std::views::filter(even))) ==
          std::vector<int>{1, 2, 3, 4});

    CHECK(vector_from_range(merge_unique(std::ranges::empty_view<int>{}, std::ranges::empty_view<int>{})).empty());
    CHECK(vector_from_range(merge_unique(silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}), std::ranges::empty_view<int>{})) == std::vector<int>{1, 2, 3});
    CHECK(vector_from_range(merge_unique(std::ranges::empty_view<int>{}, silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}))) == std::vector<int>{2, 3, 4});

    CHECK(vector_from_range(merge_unique(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) |
                  std::views::transform([](int v) { return std::vector<int>{v, v, v}; }) | std::views::join,
              silkworm::ranges::owning_view(std::vector<int>{4, 4, 4}))) ==
          std::vector<int>{1, 2, 3, 4});
}

TEST_CASE("MergeUniqueView - move results") {
    auto view = merge_unique(
        silkworm::ranges::owning_view(std::vector<std::string>{"v1"}),
        silkworm::ranges::owning_view(std::vector<std::string>{"v1"}));
    auto it = view.begin();
    {
        std::string v1 = std::move(*it);
        CHECK(v1 == "v1");
    }
    CHECK_FALSE(it == view.end());
    CHECK(++it == view.end());
}

}  // namespace silkworm::views
