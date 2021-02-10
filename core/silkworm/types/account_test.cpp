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

#include "account.hpp"

#include <catch2/catch.hpp>
#include <silkworm/common/util.hpp>

namespace silkworm {

TEST_CASE("Account RLP") {
    Account account{
        12,                                                                          // nonce
        200 * kEther,                                                                // balance
        0xdde806bc028ddb3c73ddfbe1e19676224198e5d2cb205edb40e26da2a5310d5f_bytes32,  // storage_root
        0x12580ee5fc5ea05a1a19a93cbc51830ae3607690b7c4a6996ea211aba5a966b2_bytes32,  // code_hash
    };

    Bytes encoded{};
    rlp::encode(encoded, account);

    Account decoded;
    ByteView view{encoded};
    REQUIRE(rlp::decode<Account>(view, decoded) == rlp::DecodingResult::kOk);
    CHECK(decoded == account);
}

TEST_CASE("Decode account from storage") {
    Bytes encoded{*from_hex("0f01020203e8010520f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239")};

    auto [decoded, err]{decode_account_from_storage(encoded)};
    REQUIRE(err == rlp::DecodingResult::kOk);

    CHECK(decoded.nonce == 2);
    CHECK(decoded.balance == 1000);
    CHECK(decoded.storage_root == kEmptyRoot);
    CHECK(decoded.code_hash == 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32);
    CHECK(decoded.incarnation == 5);

    CHECK(decoded.encoding_length_for_storage() == encoded.length());
    CHECK(decoded.encode_for_storage(/*omit_code_hash=*/false) == encoded);
}

}  // namespace silkworm
