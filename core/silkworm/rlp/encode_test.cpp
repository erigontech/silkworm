/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "encode.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

template <typename T>
static Bytes encoded(T x) {
    Bytes s{};
    silkworm::rlp::encode(s, x);
    return s;
}

TEST_CASE("RLP encoding") {
    SECTION("strings") {
        CHECK(to_hex(encoded(ByteView{})) == "80");
        CHECK(to_hex(encoded(*from_hex("7B"))) == "7b");
        CHECK(to_hex(encoded(*from_hex("80"))) == "8180");
        CHECK(to_hex(encoded(*from_hex("ABBA"))) == "82abba");
    }

    SECTION("uint64") {
        CHECK(to_hex(encoded(0)) == "80");
        CHECK(to_hex(encoded(1)) == "01");
        CHECK(to_hex(encoded(0x7F)) == "7f");
        CHECK(to_hex(encoded(0x80)) == "8180");
        CHECK(to_hex(encoded(0x400)) == "820400");
        CHECK(to_hex(encoded(0xFFCCB5)) == "83ffccb5");
        CHECK(to_hex(encoded(0xFFCCB5DD)) == "84ffccb5dd");
        CHECK(to_hex(encoded(0xFFCCB5DDFF)) == "85ffccb5ddff");
        CHECK(to_hex(encoded(0xFFCCB5DDFFEE)) == "86ffccb5ddffee");
        CHECK(to_hex(encoded(0xFFCCB5DDFFEE14)) == "87ffccb5ddffee14");
        CHECK(to_hex(encoded(0xFFCCB5DDFFEE1483)) == "88ffccb5ddffee1483");
    }

    SECTION("uint256") {
        CHECK(to_hex(encoded(intx::uint256{})) == "80");
        CHECK(to_hex(encoded(intx::uint256{1})) == "01");
        CHECK(to_hex(encoded(intx::uint256{0x7F})) == "7f");
        CHECK(to_hex(encoded(intx::uint256{0x80})) == "8180");
        CHECK(to_hex(encoded(intx::uint256{0x400})) == "820400");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5})) == "83ffccb5");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5DD})) == "84ffccb5dd");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5DDFF})) == "85ffccb5ddff");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5DDFFEE})) == "86ffccb5ddffee");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5DDFFEE14})) == "87ffccb5ddffee14");
        CHECK(to_hex(encoded(intx::uint256{0xFFCCB5DDFFEE1483})) == "88ffccb5ddffee1483");

        CHECK(to_hex(encoded(intx::from_string<intx::uint256>("0x10203E405060708090A0B0C0D0E0F2"))) ==
              "8f10203e405060708090a0b0c0d0e0f2");

        CHECK(to_hex(encoded(
                  intx::from_string<intx::uint256>("0x0100020003000400050006000700080009000A0B4B000C000D000E01"))) ==
              "9c0100020003000400050006000700080009000a0b4b000c000d000e01");
    }

    SECTION("vectors") {
        CHECK(to_hex(encoded(std::vector<uint64_t>{})) == "c0");
        CHECK(to_hex(encoded(std::vector<uint64_t>{0xFFCCB5, 0xFFC0B5})) == "c883ffccb583ffc0b5");
    }
}
}  // namespace silkworm
