// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <evmc/evmc.hpp>

namespace silkworm {

using namespace evmc::literals;

inline constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

// Keccak-256 hash of an empty string, KEC("").
inline constexpr evmc::bytes32 kEmptyHash{0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32};

// Keccak-256 hash of the RLP of an empty list, KEC("\xc0").
inline constexpr evmc::bytes32 kEmptyListHash{
    0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32};

// Root hash of an empty trie.
inline constexpr evmc::bytes32 kEmptyRoot{0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32};

}  // namespace silkworm
