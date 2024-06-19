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

namespace silkworm::db {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

constexpr auto kZeroAddress = 0x0000000000000000000000000000000000000000_address;
constexpr auto kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

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

}  // namespace silkworm::db
