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

#include "ecies_cipher.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/rlpx/crypto/aes.hpp>

namespace silkworm::sentry::rlpx::auth {

TEST_CASE("EciesCipher.encrypt_decrypt_message") {
    common::EccKeyPair receiver_key;

    Bytes expected_plain_text = {1, 2, 3, 4, 5};
    expected_plain_text.resize(crypto::kAESBlockSize);
    auto message = EciesCipher::encrypt_message(expected_plain_text, receiver_key.public_key(), {});
    CHECK(message.ephemeral_public_key.size() > 0);
    CHECK_FALSE(message.iv.empty());
    CHECK_FALSE(message.cipher_text.empty());
    CHECK_FALSE(message.mac.empty());
    CHECK(message.cipher_text != expected_plain_text);

    EciesCipher::PrivateKeyView private_key = receiver_key.private_key();
    Bytes plain_text = EciesCipher::decrypt_message(message, private_key, {});
    CHECK_FALSE(plain_text.empty());
    CHECK(plain_text == expected_plain_text);
}

TEST_CASE("EciesCipher.encrypt_decrypt_bytes") {
    common::EccKeyPair receiver_key;

    Bytes expected_plain_text = {1, 2, 3, 4, 5};
    expected_plain_text.resize(crypto::kAESBlockSize);
    auto cipher_text = EciesCipher::encrypt(expected_plain_text, receiver_key.public_key(), {});
    CHECK_FALSE(cipher_text.empty());
    CHECK(cipher_text != expected_plain_text);

    Bytes plain_text = EciesCipher::decrypt(cipher_text, receiver_key.private_key(), {});
    CHECK(plain_text == expected_plain_text);
}

TEST_CASE("EciesCipher.decrypt") {
    Bytes data = from_hex("043c8d19a2957e1f259cf325ad4c7f60a94bead921c7cedc135600511d51ee1d7f44d72fde3b9c9506dd3e6c69f4c10c910ea4257e42cd4335531cb2add1aed3b47e568f1473487279fdac238aa323409df92235a13d8a9036ac8d2ad3968c5f0483cd7a5fd6a441e520870644d3c61a630229b01f3e19fbd25e751ec9cfa5782abcd48a5ee406742d20a329e005761316f6963b0ec4b50f2ec3bbb022227961893a51ae568094267f27babeae3b452de67cd084fb5d03c635d7cebba86f8814b469ead9dad2504b79ca6e08e8f1db59747470054c61638000687b04a83af75111e196d253ef42697da2dd11c2bf67796b8f273a5161d7fdcfbc77332f3e0872dede7c33d6671b0b7fc7bf62db549123b0dfa66a2d76dd921faf9de35522863c8b7bc3d1a37af2d1b7f347bfdcf29b3fb7b038b86e22bd3b1a8e5b2520c52ea4ac1ce968672325bc1332b0966d2c5280b6980431e86792a485e5402aada661c6c848635d0fee662dcaa117249d346f875ffe7d85de9f6fa146d9f560bca9cee86c55028bcea3d29e38d44c4e74fd58f9cd66441f720f22349d60524aa3aae37a3f6da0cea78ca6162ce3b6b6ae3626562d6db3822f35710a95af90f4ba4eac1372dbf941e1c81567410a05fa9caaf2").value();
    Bytes private_key = from_hex("36a7edad64d51a568b00e51d3fa8cd340aa704153010edf7f55ab3066ca4ef21").value();
    Bytes mac_extra_data = from_hex("01cf").value();

    Bytes plain_text = EciesCipher::decrypt(data, private_key, mac_extra_data);
    CHECK_FALSE(plain_text.empty());
}

}  // namespace silkworm::sentry::rlpx::auth
