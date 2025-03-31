// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt_cbor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm {

TEST_CASE("CBOR encoding of empty receipts") {
    std::vector<Receipt> v{};
    Bytes encoded{cbor_encode(v)};
    CHECK(to_hex(encoded) == "f6");
}

TEST_CASE("CBOR encoding of receipts") {
    auto v{test::sample_receipts()};
    auto encoded{cbor_encode(v)};
    CHECK(to_hex(encoded) == "828400f6001a0032f05d8402f6011a00beadd0");
}

}  // namespace silkworm
