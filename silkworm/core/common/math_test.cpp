/*
   Copyright 2023 The Silkworm Authors

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

#include "math.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::math {

TEST_CASE("Integer ceil") {
    static_assert(int_ceil(-1.0E100) == std::numeric_limits<int>::min());
    static_assert(int_ceil(std::numeric_limits<int>::min()) == std::numeric_limits<int>::min());
    static_assert(int_ceil(std::numeric_limits<int>::min() + 0.5) == std::numeric_limits<int>::min() + 1);
    static_assert(int_ceil(std::numeric_limits<int>::min() + 1) == std::numeric_limits<int>::min() + 1);
    static_assert(int_ceil(-2.9) == -2);
    static_assert(int_ceil(-2.5) == -2);
    static_assert(int_ceil(-2.4) == -2);
    static_assert(int_ceil(-2.0) == -2);
    static_assert(int_ceil(-0.0) == 0);
    static_assert(int_ceil(+0.0) == 0);
    static_assert(int_ceil(2.0) == 2);
    static_assert(int_ceil(2.4) == 3);
    static_assert(int_ceil(2.5) == 3);
    static_assert(int_ceil(2.9) == 3);
    static_assert(int_ceil(std::numeric_limits<int>::max() - 1) == std::numeric_limits<int>::max() - 1);
    static_assert(int_ceil(std::numeric_limits<int>::max() - 0.5) == std::numeric_limits<int>::max());
    static_assert(int_ceil(std::numeric_limits<int>::max()) == std::numeric_limits<int>::max());
    static_assert(int_ceil(1.0E100) == std::numeric_limits<int>::max());
}

}  // namespace silkworm::math
