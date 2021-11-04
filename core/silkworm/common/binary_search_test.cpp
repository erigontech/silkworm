/*
   Copyright 2021 The Silkworm Authors

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

#include "binary_search.hpp"

#include <algorithm>
#include <cassert>
#include <vector>

#include <catch2/catch.hpp>
#include <silkworm/common/as_range.hpp>

namespace silkworm {

static void check_binary_find_if(const std::vector<int>& vec, const int value) {
    assert(std::is_sorted(vec.begin(), vec.end()));
    const auto res1{std::upper_bound(vec.begin(), vec.end(), value)};
    const auto res2{as_range::find_if(vec, [&](int x) { return x > value; })};
    CHECK(res1 == res2);
    const auto res3{binary_find_if(vec.size(), [&](size_t i) { return vec[i] > value; })};
    CHECK(static_cast<size_t>(res1 - vec.begin()) == res3);
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
