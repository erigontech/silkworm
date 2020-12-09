/*
   Copyright 2020 The Silkworm Authors

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
static T decode_hex(std::string_view hex) {
    Bytes bytes{from_hex(hex)};
    ByteView view{bytes};
    T res;
    decode<T>(view, res);
    return res;
}

template <class T>
static std::vector<T> vector_decode_hex(std::string_view hex) {
    Bytes bytes{from_hex(hex)};
    ByteView view{bytes};
    std::vector<T> res;
    decode_vector<T>(view, res);
    return res;
}

TEST_CASE("RLP decoding") {
    using Catch::Message;

    SECTION("strings") {
        CHECK(to_hex(decode_hex<Bytes>("00")) == "00");
        CHECK(to_hex(decode_hex<Bytes>("8D6F62636465666768696A6B6C6D")) == "6f62636465666768696a6b6c6d");

        CHECK_THROWS_MATCHES(decode_hex<Bytes>("C0"), DecodingError, Message("unexpected list"));
    }

    SECTION("uint64") {
        CHECK(decode_hex<uint64_t>("09") == 9);
        CHECK(decode_hex<uint64_t>("80") == 0);
        CHECK(decode_hex<uint64_t>("820505") == 0x0505);
        CHECK(decode_hex<uint64_t>("85CE05050505") == 0xCE05050505);

        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("C0"), DecodingError, Message("unexpected list"));
        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("00"), DecodingError, Message("leading zero(s)"));
        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("8105"), DecodingError, Message("non-canonical single byte"));
        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("8200F4"), DecodingError, Message("leading zero(s)"));
        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("B8020004"), DecodingError, Message("non-canonical size"));
        CHECK_THROWS_MATCHES(decode_hex<uint64_t>("8AFFFFFFFFFFFFFFFFFF7C"), DecodingError, Message("uint64 overflow"));
    }

    SECTION("uint256") {
        CHECK(decode_hex<intx::uint256>("09") == 9);
        CHECK(decode_hex<intx::uint256>("80") == 0);
        CHECK(decode_hex<intx::uint256>("820505") == 0x0505);
        CHECK(decode_hex<intx::uint256>("85CE05050505") == 0xCE05050505);
        CHECK(decode_hex<intx::uint256>("8AFFFFFFFFFFFFFFFFFF7C") ==
              intx::from_string<intx::uint256>("0xFFFFFFFFFFFFFFFFFF7C"));

        CHECK_THROWS(decode_hex<intx::uint256>("8BFFFFFFFFFFFFFFFFFF7C"));  // EOF
        CHECK_THROWS_MATCHES(decode_hex<intx::uint256>("C0"), DecodingError, Message("unexpected list"));
        CHECK_THROWS_MATCHES(decode_hex<intx::uint256>("00"), DecodingError, Message("leading zero(s)"));
        CHECK_THROWS_MATCHES(decode_hex<intx::uint256>("8105"), DecodingError, Message("non-canonical single byte"));
        CHECK_THROWS_MATCHES(decode_hex<intx::uint256>("8200F4"), DecodingError, Message("leading zero(s)"));
        CHECK_THROWS_MATCHES(decode_hex<intx::uint256>("B8020004"), DecodingError, Message("non-canonical size"));
        CHECK_THROWS_MATCHES(
            decode_hex<intx::uint256>("A101000000000000000000000000000000000000008B000000000000000000000000"),
            DecodingError, Message("uint256 overflow"));
    }

    SECTION("vectors") {
        CHECK(vector_decode_hex<intx::uint256>("C0") == std::vector<intx::uint256>{});
        CHECK(vector_decode_hex<uint64_t>("C883BBCCB583FFC0B5") == std::vector<uint64_t>{0xBBCCB5, 0xFFC0B5});
    }
}
}  // namespace silkworm::rlp
