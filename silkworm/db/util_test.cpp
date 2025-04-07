// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "util.hpp"

#include <limits>

#include <catch2/catch_test_macros.hpp>

namespace silkworm::db {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

static constexpr evmc::address kZeroAddress = 0x0000000000000000000000000000000000000000_address;
static constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

TEST_CASE("all-zero storage prefix", "[core][util]") {
    const auto address_composite_key{storage_prefix(kZeroAddress, 0)};
    CHECK(address_composite_key == Bytes(28, '\0'));

    const auto location_composite_key{storage_prefix(kZeroHash.bytes, 0)};
    CHECK(location_composite_key == Bytes(40, '\0'));
}

TEST_CASE("non-zero storage prefix for address and incarnation", "[core][util]") {
    const evmc::address address{0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address};
    const uint64_t incarnation{1};
    const auto address_composite_key{storage_prefix(address, incarnation)};
    CHECK(to_hex(address_composite_key) == "79a4d418f7887dd4d5123a41b6c8c186686ae8cb0000000000000001");
}

TEST_CASE("all-zero composite key", "[rpc][core][rawdb][util]") {
    const auto key{composite_storage_key(kZeroAddress, 0, kZeroHash.bytes)};
    CHECK(key == Bytes(60, '\0'));
}

TEST_CASE("non-zero address composite key", "[rpc][core][rawdb][util]") {
    const evmc::address address = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
    const auto key{composite_storage_key(address, 0, kZeroHash.bytes)};
    CHECK(key == from_hex("79a4d418f7887dd4d5123a41b6c8c186686ae8cb"
                          "0000000000000000"
                          "0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST_CASE("non-zero incarnation composite key", "[rpc][core][rawdb][util]") {
    const auto key{composite_storage_key(kZeroAddress, 37, kZeroHash.bytes)};
    CHECK(key == from_hex("0000000000000000000000000000000000000000"
                          "0000000000000025"
                          "0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST_CASE("non-zero hash composite key", "[rpc][core][rawdb][util]") {
    const evmc::bytes32 hash = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32;
    const auto key{composite_storage_key(kZeroAddress, 0, hash.bytes)};
    CHECK(key == from_hex("0000000000000000000000000000000000000000"
                          "0000000000000000"
                          "b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));
}

TEST_CASE("non-zero composite key", "[rpc][core][rawdb][util]") {
    const evmc::address address = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
    const evmc::bytes32 hash = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32;
    const auto key{composite_storage_key(address, 37, hash.bytes)};
    CHECK(key == from_hex("79a4d418f7887dd4d5123a41b6c8c186686ae8cb"
                          "0000000000000025"
                          "b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));
}

TEST_CASE("max incarnation composite key", "[rpc][core][rawdb][util]") {
    const auto key{composite_storage_key(kZeroAddress, std::numeric_limits<uint64_t>::max(), kZeroHash.bytes)};
    CHECK(key == from_hex("0000000000000000000000000000000000000000"
                          "ffffffffffffffff"
                          "0000000000000000000000000000000000000000000000000000000000000000"));
}

}  // namespace silkworm::db
