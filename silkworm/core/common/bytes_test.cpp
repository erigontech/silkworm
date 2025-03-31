// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bytes.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("Byteviews") {
    Bytes source{'0', '1', '2'};
    ByteView bv1(source);
    bv1.remove_prefix(3);
    REQUIRE(bv1.empty());
    ByteView bv2{};
    REQUIRE(bv2.empty());
    REQUIRE(bv1 == bv2);
    REQUIRE_FALSE(bv1.data() == bv2.data());
    REQUIRE(bv2.is_null());
}

}  // namespace silkworm
