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

#include "concat_view.hpp"

#include <algorithm>
#include <iterator>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "owning_view.hpp"

namespace silkworm::views {

static_assert(std::ranges::input_range<ConcatView<std::vector<int>, std::vector<int>>>);
static_assert(std::ranges::view<ConcatView<std::vector<int>, std::vector<int>>>);

template <std::ranges::input_range Range, typename Value = std::iter_value_t<std::ranges::iterator_t<Range>>>
std::vector<Value> vector_from_range(Range range) {
    std::vector<Value> results;
    std::ranges::copy(range, std::back_inserter(results));
    return results;
}

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
