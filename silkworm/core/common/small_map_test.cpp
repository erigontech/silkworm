// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "small_map.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("SmallMap find") {
    static constexpr SmallMap<int, double> kConfig{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    static_assert(!kConfig.find(0));
    static_assert(*kConfig.find(10) == 10.10);
    static_assert(!kConfig.find(15));
    static_assert(*kConfig.find(20) == 20.20);
    static_assert(!kConfig.find(25));
    static_assert(*kConfig.find(30) == 30.30);
    static_assert(!kConfig.find(100));
}

TEST_CASE("SmallMap to_std_map") {
    static constexpr SmallMap<int, double> kSmallMap{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    static const std::map<int, double> kStdMap{{20, 20.20}, {10, 10.10}, {30, 30.30}};
    CHECK(kSmallMap.to_std_map() == kStdMap);
}

}  // namespace silkworm
