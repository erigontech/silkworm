// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sha3_hasher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry::rlpx::crypto {

TEST_CASE("Sha3Hasher.simple") {
    Sha3Hasher hasher;
    hasher.update(Bytes{'a', 'b', 'c'});
    CHECK(to_hex(hasher.hash()) == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST_CASE("Sha3Hasher.multi") {
    Sha3Hasher hasher;
    hasher.update(from_hex("1234").value());
    hasher.update(from_hex("cafe").value());
    hasher.update(from_hex("babe").value());
    CHECK(to_hex(hasher.hash()) == "d341f310fa772d37e6966b84b37ad760811d784729b641630f6a03f729e1e20e");

    hasher.update(from_hex("5678").value());
    CHECK(to_hex(hasher.hash()) == "6de9c0166df098306abb98b112c0834c29eedee6fcba804c7c4f4568204c9d81");
}

}  // namespace silkworm::sentry::rlpx::crypto
