// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("from_hex") {
    CHECK(Hash::from_hex("foo") == std::nullopt);

    const evmc::bytes32 hash_value{0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b_bytes32};
    CHECK(Hash::from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b") == hash_value);
}

}  // namespace silkworm
