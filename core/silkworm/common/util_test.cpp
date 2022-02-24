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

#include "util.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("Split") {
    std::string source{};
    std::string delim{};
    auto output{split(source, delim)};
    CHECK((output.size() == 1 && output.at(0) == source));

    source = "aabbcc";
    output = split(source, delim);
    CHECK((output.size() == 1 && output.at(0) == source));

    delim = "b";
    output = split(source, delim);
    CHECK((output.size() == 3 && output.at(0) == "aa" && output.at(1).empty() == true && output.at(2) == "cc"));

    delim = "bb";
    output = split(source, delim);
    CHECK((output.size() == 2 && output.at(0) == "aa" && output.at(1) == "cc"));

    source = "aaaaa";
    delim = "a";
    output = split(source, delim);
    CHECK(output.size() == 5);
}

TEST_CASE("Hex") {
    CHECK(decode_hex_digit('g').has_value() == false);

    auto parsed_bytes = from_hex("");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes->empty()));

    parsed_bytes = from_hex("0x");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes->empty()));

    parsed_bytes = from_hex("0xg");
    CHECK(parsed_bytes.has_value() == false);

    Bytes expected_bytes{0x0};
    parsed_bytes = from_hex("0");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    parsed_bytes = from_hex("0x0");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    expected_bytes = {0x0a};
    parsed_bytes = from_hex("0xa");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    parsed_bytes = from_hex("0x0a");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    expected_bytes = {0x0a, 0x1f};
    parsed_bytes = from_hex("0xa1f");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    parsed_bytes = from_hex("0x0a1f");
    CHECK((parsed_bytes.has_value() == true && parsed_bytes.value() == expected_bytes));

    std::string src(24, '1');
    Bytes expected(12, 0x11);
    for (size_t i = 0; i < 24; ++i) {
        auto parsed = from_hex(src);
        CHECK((parsed.has_value() == true && parsed.value() == expected));
        src[i] = 'g';
        CHECK(from_hex(src).has_value() == false);
        src[i] = '1';
    }
}

TEST_CASE("Integrals to hex") {
    uint8_t uint8{10};
    CHECK(to_hex(uint8, true) == "0x0a");
    uint8 = 16;
    CHECK(to_hex(uint8, true) == "0x10");
    uint8 = UINT8_MAX;
    CHECK(to_hex(uint8, true) == "0xff");
    uint8 = 0;
    CHECK(to_hex(uint8, true) == "0x00");

    uint16_t uint16{256};
    CHECK(to_hex(uint16, true) == "0x0100");
    uint16 = 584;
    CHECK(to_hex(uint16, true) == "0x0248");
    uint16 = UINT16_MAX;
    CHECK(to_hex(uint16, true) == "0xffff");

    uint32_t uint32{5642869};
    CHECK(to_hex(uint32, false) == "561a75");
    uint32 = UINT32_MAX;
    CHECK(to_hex(uint32, false) == "ffffffff");

    uint32_t uint64{5642869};
    CHECK(to_hex(uint64, false) == "561a75");

}

TEST_CASE("Padding") {
    Bytes buffer;

    CHECK(to_hex(right_pad(*from_hex("a5"), 3, buffer)) == "a50000");
    CHECK(to_hex(right_pad(*from_hex("5a0b54d5dc17e0aadc383d2db4"), 3, buffer)) == "5a0b54d5dc17e0aadc383d2db4");

    CHECK(to_hex(left_pad(*from_hex("a5"), 3, buffer)) == "0000a5");
    CHECK(to_hex(left_pad(*from_hex("5a0b54d5dc17e0aadc383d2db4"), 3, buffer)) == "5a0b54d5dc17e0aadc383d2db4");

    ByteView repeatedly_padded{right_pad(*from_hex("b8c4"), 3, buffer)};
    CHECK(to_hex(repeatedly_padded) == "b8c400");
    repeatedly_padded.remove_prefix(1);
    CHECK(to_hex(repeatedly_padded) == "c400");
    repeatedly_padded = right_pad(repeatedly_padded, 4, buffer);
    CHECK(to_hex(repeatedly_padded) == "c4000000");

    repeatedly_padded = left_pad(*from_hex("b8c4"), 3, buffer);
    CHECK(to_hex(repeatedly_padded) == "00b8c4");
    repeatedly_padded.remove_suffix(1);
    CHECK(to_hex(repeatedly_padded) == "00b8");
    repeatedly_padded = left_pad(repeatedly_padded, 4, buffer);
    CHECK(to_hex(repeatedly_padded) == "000000b8");
}

TEST_CASE("Zeroless view") {
    CHECK(to_hex(zeroless_view(0x0000000000000000000000000000000000000000000000000000000000000000_bytes32)).empty());
    CHECK(to_hex(zeroless_view(0x000000000000000000000000000000000000000000000000000000000004bc00_bytes32)) ==
          "04bc00");
}

TEST_CASE("to_bytes32") {
    CHECK(to_hex(to_bytes32(*from_hex("05"))) == "0000000000000000000000000000000000000000000000000000000000000005");

    CHECK(to_hex(to_bytes32(*from_hex("0x05"))) == "0000000000000000000000000000000000000000000000000000000000000005");

    CHECK(to_hex(to_bytes32(*from_hex("9d36d8120b564f654564a91259a6ca6d37d6473827d45210190ad10f8ca451f2"))) ==
          "9d36d8120b564f654564a91259a6ca6d37d6473827d45210190ad10f8ca451f2");

    CHECK(to_hex(to_bytes32(*from_hex("0X9d36d8120b564f654564a91259a6ca6d37d6473827d45210190ad10f8ca451f2"))) ==
          "9d36d8120b564f654564a91259a6ca6d37d6473827d45210190ad10f8ca451f2");

    CHECK(to_hex(to_bytes32(*from_hex("7576351873263824fff23784264823469344629364396429864239864938264a"
                                      "8236423964bbb009874e"))) ==
          "7576351873263824fff23784264823469344629364396429864239864938264a");
}

TEST_CASE("iequals") {
    std::string a{"Hello World"};
    std::string b{"Hello wOrld"};
    std::string c{"Hello World "};
    CHECK(iequals(a, b));
    CHECK(!iequals(a, c));
}

TEST_CASE("abridge") {
    std::string a{"0x1234567890abcdef"};
    std::string b{abridge(a, 6)};
    CHECK(b == "0x1234...");
    b = abridge(a, a.length() + 1);
    CHECK(b == a);
}

TEST_CASE("parse_size") {
    std::optional<uint64_t> size{parse_size("")};
    CHECK((size && *size == 0));

    static_assert(kKibi == 1024ull);
    static_assert(kMebi == 1024ull * 1024ull);
    static_assert(kGibi == 1024ull * 1024ull * 1024ull);
    static_assert(kTebi == 1024ull * 1024ull * 1024ull * 1024ull);

    size = parse_size("128");
    CHECK((size && *size == 128));
    size = parse_size("256B");
    CHECK((size && *size == 256));
    size = parse_size("640KB");
    CHECK((size && *size == 640 * kKibi));
    size = parse_size("75MB");
    CHECK((size && *size == 75 * kMebi));
    size = parse_size("400GB");
    CHECK((size && *size == 400 * kGibi));
    size = parse_size("2TB");
    CHECK((size && *size == 2 * kTebi));
    size = parse_size(".5TB");
    CHECK((size && *size == (kTebi * 0.5)));
    size = parse_size("0.5TB");
    CHECK((size && *size == (kTebi * 0.5)));
    size = parse_size("0.5   TB");
    CHECK((size && *size == (kTebi * 0.5)));
    CHECK(!parse_size("ABBA"));
}

TEST_CASE("human_size") {
    uint64_t val{1 * kTebi};
    CHECK(human_size(val) == "1.00 TB");

    val += 512 * kGibi;
    CHECK(human_size(val) == "1.50 TB");

    val = 128;
    CHECK(human_size(val) == "128.00 B");

    val = kKibi;
    CHECK(human_size(val) == "1.00 KB");
}

}  // namespace silkworm
