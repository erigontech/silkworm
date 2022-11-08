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

#include "ssz_codec.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/lightclient/test/ssz.hpp>

namespace silkworm::ssz {

TEST_CASE("uint64_t SSZ") {
    SECTION("round-trip") {
        uint64_t a{18446744073709551615u};
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex("0xFFFFFFFFFFFFFFFF"));
        CHECK(test::decode_success<uint64_t>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<uint64_t>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<uint64_t>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<uint64_t>("0xFFFFFFFFFFFFFF") == DecodingResult::kInputTooShort);
    }
}

TEST_CASE("evmc::bytes32 SSZ") {
    SECTION("round-trip") {
        evmc::bytes32 a{0xFF000000000000000000EE00000000000000000000EE000000000000000000FF_bytes32};
        Bytes b{};
        ssz::encode(a, b);
        CHECK(b == *from_hex("0xFF000000000000000000EE00000000000000000000EE000000000000000000FF"));
        CHECK(test::decode_success<evmc::bytes32>(to_hex(b)) == a);
    }
    SECTION("decoding error") {
        CHECK(test::decode_failure<evmc::bytes32>("") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<evmc::bytes32>("00") == DecodingResult::kInputTooShort);
        CHECK(test::decode_failure<evmc::bytes32>(
                  "0xFF000000000000000000EE00000000000000000000EE000000000000000000") == DecodingResult::kInputTooShort);
    }
}

}  // namespace silkworm::ssz
