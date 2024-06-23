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

#include "clock_time.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::db::clock_time {

using std::chrono::duration_cast;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

TEST_CASE("check current time", "[rpc][common][clock_time]") {
    const auto now_before{uint64_t(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count())};
    const auto now_current{now()};
    const auto now_after{uint64_t(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count())};
    CHECK(now_before <= now_current);
    CHECK(now_current <= now_after);
}

TEST_CASE("check elapsed time", "[rpc][common][clock_time]") {
    const auto start{now()};
    const auto elapsed{since(start)};
    const auto end{now()};
    const auto window = end - start;
    CHECK(elapsed <= window);
}

}  // namespace silkworm::db::clock_time
