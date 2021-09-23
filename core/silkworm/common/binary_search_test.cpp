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

namespace silkworm {

static void check_upper_bound(const std::vector<int>& v, const int x) {
    assert(std::is_sorted(v.begin(), v.end()));
    const auto res1{std::upper_bound(v.begin(), v.end(), x)};
    const auto res2{upper_bound(v.size(), [&](size_t i) { return v[i] > x; })};
    CHECK(static_cast<size_t>(res1 - v.begin()) == res2);
}

TEST_CASE("upper_bound") {
    check_upper_bound({}, 42);
    check_upper_bound({0}, -1);
    check_upper_bound({0}, 0);
    check_upper_bound({0}, 1);
    check_upper_bound({1, 3, 3, 5}, 0);
    check_upper_bound({1, 3, 3, 5}, 1);
    check_upper_bound({1, 3, 3, 5}, 2);
    check_upper_bound({1, 3, 3, 5}, 3);
    check_upper_bound({1, 3, 3, 5}, 4);
    check_upper_bound({1, 3, 3, 5}, 5);
    check_upper_bound({1, 3, 3, 5}, 6);
}

}  // namespace silkworm
