/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "bits.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("Bits : popcount") {
    REQUIRE(popcount_16(0) == 0);
    REQUIRE(popcount_16(1) == 1);
    REQUIRE(popcount_16(0b10) == 1);
    REQUIRE(popcount_16(UINT8_MAX) == 8);
    REQUIRE(popcount_16(1 << 8) == 1);
}

TEST_CASE("Bits : bitlen") {
    REQUIRE(bitlen_16(0) == 0);
    REQUIRE(bitlen_16(1) == 1);
    REQUIRE(bitlen_16(0b10) == 2);
    REQUIRE(bitlen_16(UINT8_MAX) == 8);
    REQUIRE(bitlen_16(1 << 8) == 9);
}

TEST_CASE("Bits : ctz") {
    REQUIRE(ctz_16(0) == 16);
    REQUIRE(ctz_16(1) == 0);
    REQUIRE(ctz_16(0b10) == 1);
    REQUIRE(ctz_16(UINT8_MAX) == 0);
    REQUIRE(ctz_16(1 << 8) == 8);
}

}  // namespace silkworm
