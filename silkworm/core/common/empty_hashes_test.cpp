// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "empty_hashes.hpp"

#include <bit>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/rlp/encode.hpp>

#include "bytes.hpp"
#include "util.hpp"

namespace silkworm {

TEST_CASE("Empty hashes") {
    const ByteView empty_string;
    const ethash::hash256 hash_of_empty_string{keccak256(empty_string)};
    CHECK(std::bit_cast<evmc_bytes32>(hash_of_empty_string) == kEmptyHash);

    const Bytes empty_list_rlp(1, rlp::kEmptyListCode);
    const ethash::hash256 hash_of_empty_list_rlp{keccak256(empty_list_rlp)};
    CHECK(std::bit_cast<evmc_bytes32>(hash_of_empty_list_rlp) == kEmptyListHash);

    // See https://github.com/ethereum/yellowpaper/pull/852
    const Bytes empty_string_rlp(1, rlp::kEmptyStringCode);
    const ethash::hash256 hash_of_empty_string_rlp{keccak256(empty_string_rlp)};
    CHECK(std::bit_cast<evmc_bytes32>(hash_of_empty_string_rlp) == kEmptyRoot);
}

}  // namespace silkworm
