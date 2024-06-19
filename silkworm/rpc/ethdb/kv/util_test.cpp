/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "util.hpp"

#include <limits>

#include <catch2/catch_test_macros.hpp>

namespace silkworm::rpc::ethdb::kv {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

constexpr auto kZeroAddress = 0x0000000000000000000000000000000000000000_address;
constexpr auto kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

TEST_CASE("all-zero composite key", "[rpc][core][rawdb][util]") {
    const auto key{composite_storage_key(kZeroAddress, 0, kZeroHash.bytes)};
    CHECK(key == Bytes(60, '\0'));
}

TEST_CASE("non-zero address composite key", "[rpc][core][rawdb][util]") {
    constexpr auto address = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
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
    constexpr auto hash = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32;
    const auto key{composite_storage_key(kZeroAddress, 0, hash.bytes)};
    CHECK(key == from_hex("0000000000000000000000000000000000000000"
                          "0000000000000000"
                          "b10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"));
}

TEST_CASE("non-zero composite key", "[rpc][core][rawdb][util]") {
    constexpr auto address = 0x79a4d418f7887dd4d5123a41b6c8c186686ae8cb_address;
    constexpr auto hash = 0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6_bytes32;
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

}  // namespace silkworm::rpc::ethdb::kv
