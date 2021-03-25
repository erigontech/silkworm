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

#include "decode.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm::rlp {

template <class T>
static T decode_success(std::string_view hex) {
    Bytes bytes{*from_hex(hex)};
    ByteView view{bytes};
    T res;
    REQUIRE(decode<T>(view, res) == DecodingResult::kOk);
    CHECK(view.empty());  // check that the entire input was consumed
    return res;
}

template <class T>
static DecodingResult decode_failure(std::string_view hex) {
    Bytes bytes{*from_hex(hex)};
    ByteView view{bytes};
    T res;
    return decode<T>(view, res);
}

template <class T>
static std::vector<T> decode_vector_success(std::string_view hex) {
    Bytes bytes{*from_hex(hex)};
    ByteView view{bytes};
    std::vector<T> res;
    REQUIRE(decode_vector<T>(view, res) == DecodingResult::kOk);
    CHECK(view.empty());  // check that the entire input was consumed
    return res;
}

TEST_CASE("RLP decoding") {
    using Catch::Message;

    SECTION("strings") {
        CHECK(to_hex(decode_success<Bytes>("00")) == "00");
        CHECK(to_hex(decode_success<Bytes>("8D6F62636465666768696A6B6C6D")) == "6f62636465666768696a6b6c6d");

        CHECK(decode_failure<Bytes>("C0") == DecodingResult::kUnexpectedList);
    }

    SECTION("uint64") {
        CHECK(decode_success<uint64_t>("09") == 9);
        CHECK(decode_success<uint64_t>("80") == 0);
        CHECK(decode_success<uint64_t>("820505") == 0x0505);
        CHECK(decode_success<uint64_t>("85CE05050505") == 0xCE05050505);

        CHECK(decode_failure<uint64_t>("C0") == DecodingResult::kUnexpectedList);
        CHECK(decode_failure<uint64_t>("00") == DecodingResult::kLeadingZero);
        CHECK(decode_failure<uint64_t>("8105") == DecodingResult::kNonCanonicalSingleByte);
        CHECK(decode_failure<uint64_t>("8200F4") == DecodingResult::kLeadingZero);
        CHECK(decode_failure<uint64_t>("B8020004") == DecodingResult::kNonCanonicalSize);
        CHECK(decode_failure<uint64_t>("8AFFFFFFFFFFFFFFFFFF7C") == DecodingResult::kOverflow);
    }

    SECTION("uint256") {
        CHECK(decode_success<intx::uint256>("09") == 9);
        CHECK(decode_success<intx::uint256>("80") == 0);
        CHECK(decode_success<intx::uint256>("820505") == 0x0505);
        CHECK(decode_success<intx::uint256>("85CE05050505") == 0xCE05050505);
        CHECK(decode_success<intx::uint256>("8AFFFFFFFFFFFFFFFFFF7C") ==
              intx::from_string<intx::uint256>("0xFFFFFFFFFFFFFFFFFF7C"));

        CHECK(decode_failure<intx::uint256>("8BFFFFFFFFFFFFFFFFFF7C") == DecodingResult::kInputTooShort);
        CHECK(decode_failure<intx::uint256>("C0") == DecodingResult::kUnexpectedList);
        CHECK(decode_failure<intx::uint256>("00") == DecodingResult::kLeadingZero);
        CHECK(decode_failure<intx::uint256>("8105") == DecodingResult::kNonCanonicalSingleByte);
        CHECK(decode_failure<intx::uint256>("8200F4") == DecodingResult::kLeadingZero);
        CHECK(decode_failure<intx::uint256>("B8020004") == DecodingResult::kNonCanonicalSize);
        CHECK(decode_failure<intx::uint256>("A101000000000000000000000000000000000000008B000000000000000000000000") ==
              DecodingResult::kOverflow);
    }

    SECTION("vectors") {
        CHECK(decode_vector_success<intx::uint256>("C0") == std::vector<intx::uint256>{});
        CHECK(decode_vector_success<uint64_t>("C883BBCCB583FFC0B5") == std::vector<uint64_t>{0xBBCCB5, 0xFFC0B5});
    }
}

}  // namespace silkworm::rlp
