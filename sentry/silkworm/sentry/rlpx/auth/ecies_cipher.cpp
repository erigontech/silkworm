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

#include <cassert>
#include <memory>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/secp256k1_context.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/rlpx/crypto/aes.hpp>
#include <silkworm/sentry/rlpx/crypto/hmac.hpp>
#include <silkworm/sentry/rlpx/crypto/sha256.hpp>

namespace silkworm::sentry::rlpx::auth {

static const std::size_t kKeySize = 16;
static const std::size_t kMacSize = 32;

static Bytes kdf(ByteView secret);
using namespace crypto;

Bytes EciesCipher::compute_shared_secret(PublicKeyView public_key_view, PrivateKeyView private_key) {
    secp256k1_pubkey public_key;
    assert(public_key_view.size() == sizeof(public_key.data));
    memcpy(public_key.data, public_key_view.data().data(), sizeof(public_key.data));

    Bytes shared_secret(kKeySize * 2, 0);
    SecP256K1Context ctx;
    bool ok = ctx.compute_ecdh_secret(shared_secret, &public_key, private_key);
    if (!ok) {
        throw std::runtime_error("Failed to ECDH-agree public and private key");
    }

    return shared_secret;
}

EciesCipher::Message EciesCipher::encrypt_message(
    ByteView plain_text,
    PublicKeyView public_key_view,
    ByteView mac_extra_data) {
    common::EccKeyPair ephemeral_key_pair;

    Bytes shared_secret = kdf(compute_shared_secret(public_key_view, ephemeral_key_pair.private_key()));
    ByteView aes_key(shared_secret.data(), kKeySize);
    ByteView mac_key(&shared_secret[kKeySize], kKeySize);

    Bytes iv = aes_make_iv();

    Bytes cipher_text = aes_encrypt(plain_text, aes_key, iv);
    Bytes mac = hmac(sha256(mac_key), iv, cipher_text, mac_extra_data);

    return {
        ephemeral_key_pair.public_key(),
        std::move(iv),
        std::move(cipher_text),
        std::move(mac),
    };
}

Bytes EciesCipher::decrypt_message(
    const EciesCipher::Message& message,
    PrivateKeyView private_key,
    ByteView mac_extra_data) {
    Bytes shared_secret = kdf(compute_shared_secret(message.ephemeral_public_key, private_key));
    ByteView aes_key(shared_secret.data(), kKeySize);
    ByteView mac_key(&shared_secret[kKeySize], kKeySize);

    Bytes mac = hmac(sha256(mac_key), message.iv, message.cipher_text, mac_extra_data);
    if (mac != message.mac) {
        throw std::runtime_error("Invalid MAC");
    }

    return aes_decrypt(message.cipher_text, aes_key, message.iv);
}

size_t EciesCipher::round_up_to_block_size(size_t size) {
    return aes_round_up_to_block_size(size);
}

size_t EciesCipher::estimate_encrypted_size(size_t size) {
    return size + SecP256K1Context::kPublicKeySizeUncompressed + kAESBlockSize + kMacSize;
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
// Since sha256 produces the right size, one iteration is enough.
static Bytes kdf(ByteView secret) {
    assert(secret.size() == kKeySize * 2);
    Bytes data(sizeof(uint32_t), 0);
    endian::store_big_u32(data.data(), 1);
    data += secret;
    return sha256(data);
}

Bytes EciesCipher::serialize_message(const Message& message) {
    secp256k1_pubkey public_key;
    assert(message.ephemeral_public_key.size() == sizeof(public_key.data));
    memcpy(public_key.data, message.ephemeral_public_key.data().data(), sizeof(public_key.data));

    SecP256K1Context ctx;
    Bytes key_data = ctx.serialize_public_key(&public_key, /* is_compressed = */ false);

    Bytes data;
    data.reserve(
        key_data.size() +
        message.iv.size() +
        message.cipher_text.size() +
        message.mac.size());
    data.append(key_data);
    data.append(message.iv);
    data.append(message.cipher_text);
    data.append(message.mac);
    return data;
}

EciesCipher::Message EciesCipher::deserialize_message(ByteView message_data) {
    const std::size_t key_size = SecP256K1Context::kPublicKeySizeUncompressed;
    const std::size_t iv_size = kAESBlockSize;
    const std::size_t mac_size = kMacSize;

    const std::size_t min_size = key_size + iv_size + mac_size;
    if (message_data.size() < min_size) {
        throw std::runtime_error("Message data is too short");
    }
    const std::size_t cipher_text_size = message_data.size() - min_size;

    Bytes key_data{&message_data[0], key_size};
    Bytes iv{&message_data[key_size], iv_size};
    Bytes cipher_text{&message_data[key_size + iv_size], cipher_text_size};
    Bytes mac{&message_data[key_size + iv_size + cipher_text_size], mac_size};

    auto ephemeral_public_key = common::EccPublicKey::deserialize_std(key_data);

    return {
        std::move(ephemeral_public_key),
        std::move(iv),
        std::move(cipher_text),
        std::move(mac),
    };
}

Bytes EciesCipher::encrypt(ByteView plain_text, PublicKeyView public_key, ByteView mac_extra_data) {
    return serialize_message(encrypt_message(plain_text, public_key, mac_extra_data));
}

Bytes EciesCipher::decrypt(ByteView message_data, PrivateKeyView private_key, ByteView mac_extra_data) {
    return decrypt_message(deserialize_message(message_data), private_key, mac_extra_data);
}

}  // namespace silkworm::sentry::rlpx::auth
