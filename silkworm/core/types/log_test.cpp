// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Log RLP encoding") {
    Log sample_log1{
        0xea674fdde714fd979de3edf0f56aa9716b898ec8_address,
        {},
        *from_hex("0x010043"),
    };
    std::string_view expected_rlp1{"da94ea674fdde714fd979de3edf0f56aa9716b898ec8c083010043"};

    SECTION("own encode method") {
        Bytes encoded;
        rlp::encode(encoded, sample_log1);
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        CHECK((to_hex(encoded) == expected_rlp1));
    }

    SECTION("variadic struct encode") {
        Bytes encoded;
        rlp::encode(
            encoded,
            sample_log1.address,
            sample_log1.topics,
            sample_log1.data);
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        CHECK((to_hex(encoded) == expected_rlp1));
    }
}

}  // namespace silkworm
