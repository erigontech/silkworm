/*
   Copyright 2021 The Silkworm Authors

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

#include "endian.hpp"

#include <catch2/catch.hpp>

namespace silkworm::endian {

TEST_CASE("32-bit Endian") {
    uint8_t bytes[4];
    uint32_t value{0x12345678};

    store_big_u32(bytes, value);
    CHECK(bytes[0] == 0x12);
    CHECK(bytes[1] == 0x34);
    CHECK(bytes[2] == 0x56);
    CHECK(bytes[3] == 0x78);

    uint32_t be{load_big_u32(bytes)};
    CHECK(be == value);

    uint32_t le{load_little_u32(bytes)};
    CHECK(le == 0x78563412);
}

TEST_CASE("64-bit Endian") {
    uint8_t bytes[8];
    uint64_t value{0x123456789abcdef0};

    store_big_u64(bytes, value);
    CHECK(bytes[0] == 0x12);
    CHECK(bytes[1] == 0x34);
    CHECK(bytes[2] == 0x56);
    CHECK(bytes[3] == 0x78);
    CHECK(bytes[4] == 0x9a);
    CHECK(bytes[5] == 0xbc);
    CHECK(bytes[6] == 0xde);
    CHECK(bytes[7] == 0xf0);

    uint64_t be{load_big_u64(bytes)};
    CHECK(be == value);

    uint64_t le{load_little_u64(bytes)};
    CHECK(le == 0xf0debc9a78563412);
}

}  // namespace silkworm::endian
