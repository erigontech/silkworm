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

#include "merge_unique_many_view.hpp"

#include <catch2/catch_test_macros.hpp>

#include "owning_view.hpp"
#include "vector_from_range.hpp"

namespace silkworm::views {

static_assert(std::ranges::input_range<MergeUniqueManyView<std::vector<std::vector<int>>>>);
static_assert(std::ranges::view<MergeUniqueManyView<std::vector<std::vector<int>>>>);

template <std::ranges::input_range TRange>
std::vector<TRange> ranges(TRange r1, TRange r2) {
    std::vector<TRange> results;
    results.emplace_back(std::move(r1));
    results.emplace_back(std::move(r2));
    return results;
}

// Skip to avoid Windows error C3889: call to object of class type 'std::ranges::_Begin::_Cpo': no matching call operator found
// Unable to reproduce: https://godbolt.org/z/3jd5brKMj
#ifndef _WIN32
TEST_CASE("MergeUniqueManyView") {
    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4})))) ==
          std::vector<int>{1, 2, 3, 4});

    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3, 4, 5}),
              silkworm::ranges::owning_view(std::vector<int>{3, 4, 5, 6, 7})))) ==
          std::vector<int>{1, 2, 3, 4, 5, 6, 7});

    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3, 4, 5, 5, 5}),
              silkworm::ranges::owning_view(std::vector<int>{3, 4, 5, 6, 7})))) ==
          std::vector<int>{1, 2, 3, 4, 5, 6, 7});

    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{0, 2, 2, 2, 4, 5, 6, 6, 7, 7}),
              silkworm::ranges::owning_view(std::vector<int>{0, 0, 1, 2, 3, 5, 5, 6, 8, 9})))) ==
          std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9});

    using IntPredicate = std::function<bool(int)>;
    IntPredicate even = [](int x) { return x % 2 == 0; };
    IntPredicate odd = [](int x) { return x % 2 == 1; };
    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(even),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}) | std::views::filter(odd)))) ==
          std::vector<int>{2, 3});
    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::filter(odd),
              silkworm::ranges::owning_view(std::vector<int>{2, 3, 4}) | std::views::filter(even)))) ==
          std::vector<int>{1, 2, 3, 4});

    CHECK(vector_from_range(merge_unique_many(ranges(std::vector<int>{}, std::vector<int>{}))).empty());
    CHECK(vector_from_range(merge_unique_many(ranges(silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}), silkworm::ranges::owning_view(std::vector<int>{})))) == std::vector<int>{1, 2, 3});
    CHECK(vector_from_range(merge_unique_many(ranges(silkworm::ranges::owning_view(std::vector<int>{}), silkworm::ranges::owning_view(std::vector<int>{2, 3, 4})))) == std::vector<int>{2, 3, 4});

    using IntToVectorFunc = std::function<std::vector<int>(int)>;
    CHECK(vector_from_range(merge_unique_many(ranges(
              silkworm::ranges::owning_view(std::vector<int>{1, 2, 3}) | std::views::transform(IntToVectorFunc{[](int v) { return std::vector<int>{v, v, v}; }}) | std::views::join,
              silkworm::ranges::owning_view(std::vector<int>{4, 4, 4}) | std::views::transform(IntToVectorFunc{[](int v) { return std::vector<int>{v}; }}) | std::views::join))) ==
          std::vector<int>{1, 2, 3, 4});
}
#endif  // _WIN32

}  // namespace silkworm::views
