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

#include "account.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm {

TEST_CASE("Decode account from storage") {
    SECTION("Correct payload") {
        Bytes encoded{*from_hex("0f01020203e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kOk);

        CHECK(decoded.nonce == 2);
        CHECK(decoded.balance == 1000);
        CHECK(decoded.code_hash == 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32);
        CHECK(decoded.incarnation == 5);

        CHECK(decoded.encoding_length_for_storage() == encoded.length());
        CHECK(decoded.encode_for_storage() == encoded);
    }

    SECTION("Correct payload only incarnation") {
        Bytes encoded{*from_hex("0f01020203e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};
        auto [incarnation, err]{Account::incarnation_from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kOk);
        REQUIRE(incarnation == 5);
    }

    SECTION("Empty payload") {
        Bytes encoded{};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kOk);

        CHECK(decoded.nonce == 0);
        CHECK(decoded.balance == 0);
        CHECK(decoded.code_hash == kEmptyHash);
        CHECK(decoded.incarnation == 0);
    }

    SECTION("One zero byte payload") {
        Bytes encoded{*from_hex("00")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kOk);
    }

    SECTION("One non-zero byte payload") {
        Bytes encoded{*from_hex("04")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kInputTooShort);
    }

    SECTION("One >15 byte head plus 1byte") {
        Bytes encoded{*from_hex("1e01")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kInvalidFieldset);
    }

    SECTION("Too short payload") {
        Bytes encoded{*from_hex("0f")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kInputTooShort);
    }

    SECTION("Wrong nonce payload") {
        Bytes encoded{*from_hex("01020001")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kLeadingZero);
    }

    SECTION("Wrong code_hash payload") {
        Bytes encoded{*from_hex("0x0805c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4")};
        auto [decoded, err]{Account::from_encoded_storage(encoded)};
        REQUIRE(err == DecodingResult::kUnexpectedLength);
    }
}

}  // namespace silkworm
