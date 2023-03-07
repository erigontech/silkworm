/*
   Copyright 2021 The Silkrpc Authors

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

#include <catch2/catch.hpp>

namespace silkrpc::clock_time {

using Catch::Matchers::Message;

using std::chrono::duration_cast;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

TEST_CASE("check current time", "[silkrpc][common][clock_time]") {
    const auto now_before{duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count()};
    const auto now{clock_time::now()};
    const auto now_after{duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count()};
    CHECK(now_before <= now);
    CHECK(now <= now_after);
}

TEST_CASE("check elapsed time", "[silkrpc][common][clock_time]") {
    const auto start{clock_time::now()};
    const auto elapsed{clock_time::since(start)};
    const auto end{clock_time::now()};
    const auto window = end - start;
    CHECK(elapsed <= window);
}

} // namespace silkrpc::clock_time
