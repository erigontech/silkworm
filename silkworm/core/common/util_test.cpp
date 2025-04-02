/*
   Copyright 2022 The Silkworm Authors

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

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

using namespace evmc::literals;

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

    expected_bytes = Bytes{0x0a};
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

TEST_CASE("Zeroless view") {
    SECTION("from bytes32") {
        CHECK(to_hex(zeroless_view((0x0000000000000000000000000000000000000000000000000000000000000000_bytes32).bytes)).empty());
        CHECK(to_hex(zeroless_view((0x000000000000000000000000000000000000000000000000000000000004bc00_bytes32).bytes)) ==
              "04bc00");
        CHECK(to_hex(zeroless_view((0x100000000000000000000000000000000000000000000000000000000004bc00_bytes32).bytes)) ==
              "100000000000000000000000000000000000000000000000000000000004bc00");
    }
    SECTION("from Bytes") {
        Bytes block_num_as_bytes(sizeof(BlockNum), '\0');
        intx::be::unsafe::store<uint64_t>(block_num_as_bytes.data(), 12'209'569);
        CHECK(to_hex(zeroless_view(block_num_as_bytes)) == "ba4da1");
    }
    SECTION("from ByteView") {
        CHECK(to_hex(zeroless_view(ByteView{})).empty());
        CHECK(to_hex(zeroless_view(ByteView{{0x01, 0x00}})) == "0100");
        CHECK(to_hex(zeroless_view(ByteView{{00, 01}})) == "01");
    }
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
    b = abridge(a, a.size() + 1);
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
    CHECK((size && *size == (kTebi / 2)));
    size = parse_size("0.5TB");
    CHECK((size && *size == (kTebi / 2)));
    size = parse_size("0.5   TB");
    CHECK((size && *size == (kTebi / 2)));
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

TEST_CASE("intx::uint256 from scientific notation string") {
    static constexpr intx::uint256 kMainnetTTD{intx::from_string<intx::uint256>("58750000000000000000000")};
    CHECK(from_string_sci<intx::uint256>("5.875e+22") == kMainnetTTD);
    CHECK(from_string_sci<intx::uint256>("58750000000000000000000") == kMainnetTTD);

    static constexpr intx::uint256 kSepoliaTTD{intx::from_string<intx::uint256>("17000000000000000")};
    CHECK(from_string_sci<intx::uint256>("1.7e+16") == kSepoliaTTD);
    CHECK(from_string_sci<intx::uint256>("17000000000000000") == kSepoliaTTD);

    CHECK(from_string_sci<intx::uint256>("0") == intx::from_string<intx::uint256>("0"));
    CHECK(from_string_sci<intx::uint256>("0e+0") == intx::from_string<intx::uint256>("0"));
    CHECK(from_string_sci<intx::uint256>("0.0e+1") == intx::from_string<intx::uint256>("0"));
    CHECK(from_string_sci<intx::uint256>("18") == intx::from_string<intx::uint256>("18"));
    CHECK(from_string_sci<intx::uint256>("18e+0") == intx::from_string<intx::uint256>("18"));
    CHECK(from_string_sci<intx::uint256>("18e+1") == intx::from_string<intx::uint256>("180"));
    CHECK(from_string_sci<intx::uint256>("18.1e+1") == intx::from_string<intx::uint256>("181"));
    CHECK(from_string_sci<intx::uint256>("18e+2") == intx::from_string<intx::uint256>("1800"));
    CHECK(from_string_sci<intx::uint256>("18.1e+2") == intx::from_string<intx::uint256>("1810"));
    CHECK(from_string_sci<intx::uint256>("18.12e+2") == intx::from_string<intx::uint256>("1812"));

    static constexpr char kMaxFixedDecimalNotation[] = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    CHECK(from_string_sci<intx::uint256>(kMaxFixedDecimalNotation) == std::numeric_limits<intx::uint256>::max());
    static constexpr char kMaxScientificNotation[] = "1.15792089237316195423570985008687907853269984665640564039457584007913129639935e+77";
    CHECK(from_string_sci<intx::uint256>(kMaxScientificNotation) == std::numeric_limits<intx::uint256>::max());
}

TEST_CASE("intx::uint256 to_float") {
    CHECK(to_float(0) == 0.f);
    CHECK(to_float(1) == 1.f);
    CHECK(to_float(24) == 24.f);
    CHECK(to_float(intx::from_string<intx::uint256>("1000000000000000000000000")) == 1e24f);
}

TEST_CASE("print intx::uint256") {
    const intx::uint256 i{intx::from_string<intx::uint256>("1000000000000000000000000")};
    CHECK(test_util::null_stream() << i);
}

TEST_CASE("print Bytes") {
    Bytes b{};
    CHECK(test_util::null_stream() << b);
}

TEST_CASE("print ByteView") {
    ByteView bv1;
    CHECK(test_util::null_stream() << bv1);
    Bytes b{*from_hex("0x0608")};
    ByteView bv2{b};
    CHECK(test_util::null_stream() << bv2);
}

}  // namespace silkworm
