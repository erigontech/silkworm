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

#include "ecies_cipher.hpp"
#include <catch2/catch.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

namespace silkworm::sentry::rlpx::auth {

TEST_CASE("EciesCipher.encrypt_decrypt_message") {
    common::EccKeyPair receiver_key;

    Bytes expected_plain_text = {1, 2, 3, 4, 5};
    EciesCipher::PublicKey public_key = receiver_key.public_key();
    auto message = EciesCipher::encrypt_message(expected_plain_text, public_key);
    CHECK_FALSE(message.ephemeral_public_key.empty());
    CHECK_FALSE(message.iv.empty());
    CHECK_FALSE(message.cipher_text.empty());
    CHECK_FALSE(message.mac.empty());
    CHECK(message.cipher_text != expected_plain_text);

    EciesCipher::PrivateKeyView private_key = receiver_key.private_key();
    Bytes plain_text = EciesCipher::decrypt_message(message, private_key);
    CHECK_FALSE(plain_text.empty());
    CHECK(plain_text == expected_plain_text);
}

TEST_CASE("EciesCipher.encrypt_decrypt_bytes") {
    common::EccKeyPair receiver_key;

    Bytes expected_plain_text = {1, 2, 3, 4, 5};
    EciesCipher::PublicKey public_key = receiver_key.public_key();
    auto cipher_text = EciesCipher::encrypt(expected_plain_text, receiver_key.public_key());
    CHECK_FALSE(cipher_text.empty());
    CHECK(cipher_text != expected_plain_text);

    Bytes plain_text = EciesCipher::decrypt(cipher_text, receiver_key.private_key());
    CHECK(plain_text == expected_plain_text);
}

}  // silkworm::sentry::rlpx::auth
