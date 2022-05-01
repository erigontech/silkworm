/*
   Copyright 2020-2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless CHECKd by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "bits.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("Bits : popcount") {
    CHECK(popcount_16(0) == 0);
    CHECK(popcount_16(1) == 1);
    CHECK(popcount_16(0b10) == 1);
    CHECK(popcount_16(0b11) == 2);
    CHECK(popcount_16(0b111) == 3);
    CHECK(popcount_16(0b101) == 2);
    CHECK(popcount_16(UINT8_MAX) == 8);
    CHECK(popcount_16(1 << 8) == 1);
}

TEST_CASE("Bits : ctz_16") {
    CHECK(ctz_16(0b0000000000000000) == 16);
    CHECK(ctz_16(0b0000000000000001) == 0);
    CHECK(ctz_16(0b0000000000000010) == 1);
    CHECK(ctz_16(0b0000000000000100) == 2);
    CHECK(ctz_16(0b1000000000000100) == 2);
    CHECK(ctz_16(0b1000000000000000) == 15);
    CHECK(ctz_16(1 << 8) == 8);
}

TEST_CASE("Bits : clz_16") {
    CHECK(clz_16(0b0000000000000000) == 16);
    CHECK(clz_16(0b0000000000000001) == 15);
    CHECK(clz_16(0b0000000000000010) == 14);
    CHECK(clz_16(0b0000000000000100) == 13);
    CHECK(clz_16(0b1000000000000100) == 0);
    CHECK(clz_16(0b1000000000000000) == 0);
    CHECK(clz_16(1 << 8) == 7);
}
TEST_CASE("Bits : bitlen") {
    CHECK(bitlen_16(0) == 0);
    CHECK(bitlen_16(0b01) == 1);
    CHECK(bitlen_16(0b10) == 2);
    CHECK(bitlen_16(UINT8_MAX) == 8);
    CHECK(bitlen_16(UINT16_MAX) == 16);
    CHECK(bitlen_16(1 << 8) == 9);
}

}  // namespace silkworm
