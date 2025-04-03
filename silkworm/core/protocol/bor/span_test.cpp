// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "span.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::protocol::bor {

// See https://docs.soliditylang.org/en/latest/abi-spec.html
TEST_CASE("GetCurrentSpan ABI") {
    static constexpr std::string_view kFunctionSignature{"getCurrentSpan()"};
    const ethash::hash256 hash{keccak256(string_view_to_byte_view(kFunctionSignature))};
    const ByteView selector{ByteView{hash.bytes}.substr(0, 4)};
    CHECK(to_hex(selector) == "af26aa96");
}

}  // namespace silkworm::protocol::bor
