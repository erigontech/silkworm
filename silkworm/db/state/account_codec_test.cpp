// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "account_codec.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("Decode account from storage") {
    SECTION("Correct payload") {
        const Bytes encoded{*from_hex("0f01020203e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};
        const auto decoded = AccountCodec::from_encoded_storage(encoded);
        REQUIRE(decoded);

        CHECK(decoded->nonce == 2);
        CHECK(decoded->balance == 1000);
        CHECK(decoded->code_hash == 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32);
        CHECK(decoded->incarnation == 5);

        CHECK(AccountCodec::encoding_length_for_storage(*decoded) == encoded.size());
        CHECK(AccountCodec::encode_for_storage(*decoded) == encoded);
    }

    SECTION("Correct payload only incarnation") {
        const Bytes encoded{*from_hex("0f01020203e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};
        const auto incarnation = AccountCodec::incarnation_from_encoded_storage(encoded);
        CHECK(incarnation == 5);
    }

    SECTION("Empty payload") {
        const Bytes encoded{};
        const auto decoded = AccountCodec::from_encoded_storage(encoded);
        REQUIRE(decoded);

        CHECK(decoded->nonce == 0);
        CHECK(decoded->balance == 0);
        CHECK(decoded->code_hash == kEmptyHash);
        CHECK(decoded->incarnation == 0);
    }

    SECTION("One zero byte payload") {
        const Bytes encoded{*from_hex("00")};
        CHECK(AccountCodec::from_encoded_storage(encoded));
    }

    SECTION("One non-zero byte payload") {
        const Bytes encoded{*from_hex("04")};
        CHECK(AccountCodec::from_encoded_storage(encoded) == tl::unexpected{DecodingError::kInputTooShort});
    }

    SECTION("One >15 byte head plus 1byte") {
        const Bytes encoded{*from_hex("1e01")};
        CHECK(AccountCodec::from_encoded_storage(encoded) == tl::unexpected{DecodingError::kInvalidFieldset});
    }

    SECTION("Too short payload") {
        const Bytes encoded{*from_hex("0f")};
        CHECK(AccountCodec::from_encoded_storage(encoded) == tl::unexpected{DecodingError::kInputTooShort});
    }

    SECTION("Wrong nonce payload") {
        const Bytes encoded{*from_hex("01020001")};
        CHECK(AccountCodec::from_encoded_storage(encoded) == tl::unexpected{DecodingError::kLeadingZero});
    }

    SECTION("Wrong code_hash payload") {
        const Bytes encoded{*from_hex("0x0805c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4")};
        CHECK(AccountCodec::from_encoded_storage(encoded) == tl::unexpected{DecodingError::kUnexpectedLength});
    }
}

TEST_CASE("AccountCodec::encode_for_storage_v3") {
    CHECK(AccountCodec::encode_for_storage_v3(Account{2, 3, kEmptyRoot, 4}) ==
          *from_hex("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104"));
    CHECK(AccountCodec::encode_for_storage_v3(Account{2, 3, kEmptyHash, 4}) == *from_hex("01020103000104"));
    CHECK(AccountCodec::encode_for_storage_v3(Account{0, 3, kEmptyHash, 4}) == *from_hex("000103000104"));
    CHECK(AccountCodec::encode_for_storage_v3(Account{2, 0, kEmptyHash, 4}) == *from_hex("010200000104"));
    CHECK(AccountCodec::encode_for_storage_v3(Account{2, 3, kEmptyHash, 0}) == *from_hex("010201030000"));
}

TEST_CASE("AccountCodec::from_encoded_storage_v3") {
    const auto decode = [](std::string_view payload) -> tl::expected<Account, DecodingError> {
        return AccountCodec::from_encoded_storage_v3(*from_hex(payload));
    };

    CHECK(decode("010201032056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210104") ==
          Account{2, 3, kEmptyRoot, 4});
    CHECK(decode("01020103000104") == Account{2, 3, kEmptyHash, 4});
    CHECK(decode("000103000104") == Account{0, 3, kEmptyHash, 4});
    CHECK(decode("010200000104") == Account{2, 0, kEmptyHash, 4});
    CHECK(decode("010201030000") == Account{2, 3, kEmptyHash, 0});
    CHECK(decode("00000000") == Account{});
    CHECK(decode("01020203e820f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105") ==
          Account{2, 1000, 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32, 5});

    // wrong nonce
    CHECK(decode("020001") == tl::unexpected{DecodingError::kLeadingZero});

    // wrong code hash
    CHECK(decode("01020203e822f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105") ==
          tl::unexpected{DecodingError::kUnexpectedLength});

    SECTION("Too short payloads") {
        std::vector<std::string_view> payloads{
            "",
            "00",
            "0000",
            "000000",
            "0f",
            "0102",
            "01020203e8",
            "0805c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4",
        };
        for (const auto payload : payloads) {
            CHECK(decode(payload) == tl::unexpected{DecodingError::kInputTooShort});
        }
    }
}

}  // namespace silkworm::db::state
