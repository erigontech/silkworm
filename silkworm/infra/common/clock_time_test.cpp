// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "clock_time.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::clock_time {

using std::chrono::duration_cast;
using std::chrono::nanoseconds;
using std::chrono::steady_clock;

TEST_CASE("check current time", "[infra][common][clock_time]") {
    const auto now_before{duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count()};
    const uint64_t now_current{now()};
    const auto now_after{duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count()};
    CHECK(static_cast<uint64_t>(now_before) <= now_current);
    CHECK(now_current <= static_cast<uint64_t>(now_after));
}

TEST_CASE("check elapsed time", "[infra][common][clock_time]") {
    const auto start{now()};
    const auto elapsed{since(start)};
    const auto end{now()};
    const auto window = end - start;
    CHECK(elapsed <= window);
}

}  // namespace silkworm::clock_time
