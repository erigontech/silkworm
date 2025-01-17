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

#include "decode.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

#include "decode_vector.hpp"

namespace silkworm::rlp {

template <class T>
static T decode_success(std::string_view hex) {
    Bytes bytes{*from_hex(hex)};
    ByteView view{bytes};
    T res{};
    REQUIRE(decode(view, res));
    return res;
}

template <class T>
static DecodingError decode_failure(std::string_view hex) {
    Bytes bytes{*from_hex(hex)};
    ByteView view{bytes};
    T x;
    DecodingResult res{decode(view, x)};
    REQUIRE(!res);
    return res.error();
}

TEST_CASE("RLP decoding") {
    SECTION("strings") {
        CHECK(to_hex(decode_success<Bytes>("00")) == "00");
        CHECK(to_hex(decode_success<Bytes>("8D6F62636465666768696A6B6C6D")) == "6f62636465666768696a6b6c6d");

        CHECK(decode_failure<Bytes>("8D6F62636465666768696A6B6C6Daa") == DecodingError::kInputTooLong);
        CHECK(decode_failure<Bytes>("C0") == DecodingError::kUnexpectedList);
    }

    SECTION("uint64") {
        CHECK(decode_success<uint64_t>("09") == 9);
        CHECK(decode_success<uint64_t>("80") == 0);
        CHECK(decode_success<uint64_t>("820505") == 0x0505);
        CHECK(decode_success<uint64_t>("85CE05050505") == 0xCE05050505);

        CHECK(decode_failure<uint64_t>("85CE05050505aa") == DecodingError::kInputTooLong);
        CHECK(decode_failure<uint64_t>("C0") == DecodingError::kUnexpectedList);
        CHECK(decode_failure<uint64_t>("00") == DecodingError::kLeadingZero);
        CHECK(decode_failure<uint64_t>("8105") == DecodingError::kNonCanonicalSize);
        CHECK(decode_failure<uint64_t>("8200F4") == DecodingError::kLeadingZero);
        CHECK(decode_failure<uint64_t>("B8020004") == DecodingError::kNonCanonicalSize);
        CHECK(decode_failure<uint64_t>("8AFFFFFFFFFFFFFFFFFF7C") == DecodingError::kOverflow);
    }

    SECTION("uint256") {
        CHECK(decode_success<intx::uint256>("09") == 9);
        CHECK(decode_success<intx::uint256>("80") == 0);
        CHECK(decode_success<intx::uint256>("820505") == 0x0505);
        CHECK(decode_success<intx::uint256>("85CE05050505") == 0xCE05050505);
        CHECK(decode_success<intx::uint256>("8AFFFFFFFFFFFFFFFFFF7C") ==
              intx::from_string<intx::uint256>("0xFFFFFFFFFFFFFFFFFF7C"));

        CHECK(decode_failure<intx::uint256>("8BFFFFFFFFFFFFFFFFFF7C") == DecodingError::kInputTooShort);
        CHECK(decode_failure<intx::uint256>("8AFFFFFFFFFFFFFFFFFF7Caa") == DecodingError::kInputTooLong);
        CHECK(decode_failure<intx::uint256>("C0") == DecodingError::kUnexpectedList);
        CHECK(decode_failure<intx::uint256>("00") == DecodingError::kLeadingZero);
        CHECK(decode_failure<intx::uint256>("8105") == DecodingError::kNonCanonicalSize);
        CHECK(decode_failure<intx::uint256>("8200F4") == DecodingError::kLeadingZero);
        CHECK(decode_failure<intx::uint256>("B8020004") == DecodingError::kNonCanonicalSize);
        CHECK(decode_failure<intx::uint256>("A101000000000000000000000000000000000000008B000000000000000000000000") ==
              DecodingError::kOverflow);
    }

    SECTION("lists") {
        CHECK(decode_success<std::vector<intx::uint256>>("C0").empty());
        CHECK(decode_success<std::vector<uint64_t>>("C883BBCCB583FFC0B5") == std::vector<uint64_t>{0xBBCCB5, 0xFFC0B5});
        CHECK(decode_failure<std::vector<uint64_t>>("C883BBCCB583FFC0B5aa") == DecodingError::kInputTooLong);
    }
}

}  // namespace silkworm::rlp
