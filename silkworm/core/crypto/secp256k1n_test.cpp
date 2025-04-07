// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "secp256k1n.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("is_valid_signature") {
    bool homestead = false;
    CHECK(!is_valid_signature(0, 0, homestead));
    CHECK(!is_valid_signature(0, 1, homestead));
    CHECK(!is_valid_signature(1, 0, homestead));
    CHECK(is_valid_signature(1, 1, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn + 1, homestead));
    CHECK(is_valid_signature(kSecp256k1n - 1, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n, homestead));

    homestead = true;
    CHECK(!is_valid_signature(0, 0, homestead));
    CHECK(!is_valid_signature(0, 1, homestead));
    CHECK(!is_valid_signature(1, 0, homestead));
    CHECK(is_valid_signature(1, 1, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn, homestead));
    CHECK(!is_valid_signature(1, kSecp256k1Halfn + 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n, homestead));
}

}  // namespace silkworm
