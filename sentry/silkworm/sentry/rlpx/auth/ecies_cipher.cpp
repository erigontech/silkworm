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
#include <gsl/util>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <silkpre/sha256.h>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/secp256k1_context.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/random.hpp>

namespace silkworm::sentry::rlpx::auth {

static const std::size_t kKeySize = 16;
static const std::size_t kMacSize = 32;

static Bytes kdf(ByteView secret);
static Bytes aes_encrypt(ByteView plain_text, ByteView key, ByteView iv);
static Bytes aes_decrypt(ByteView cipher_text, ByteView key, ByteView iv);
static Bytes sha256(ByteView data);
static Bytes hmac(ByteView key, ByteView data1, ByteView data2, ByteView data3);

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

EciesCipher::Message EciesCipher::encrypt_message(ByteView plain_text, PublicKeyView public_key_view, ByteView mac_extra_data) {
    common::EccKeyPair ephemeral_key_pair;

    Bytes shared_secret = kdf(compute_shared_secret(public_key_view, ephemeral_key_pair.private_key()));
    ByteView aes_key(shared_secret.data(), kKeySize);
    ByteView mac_key(&shared_secret[kKeySize], kKeySize);

    Bytes iv = common::random_bytes(AES_BLOCK_SIZE);

    Bytes cypher_text = aes_encrypt(plain_text, aes_key, iv);
    Bytes mac = hmac(sha256(mac_key), iv, cypher_text, mac_extra_data);

    return {
        ephemeral_key_pair.public_key(),
        std::move(iv),
        std::move(cypher_text),
        std::move(mac),
    };
}

Bytes EciesCipher::decrypt_message(const EciesCipher::Message& message, PrivateKeyView private_key, ByteView mac_extra_data) {
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
    return (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
}

size_t EciesCipher::estimate_encrypted_size(size_t size) {
    return size
        + SecP256K1Context::kPublicKeySizeUncompressed
        + AES_BLOCK_SIZE
        + kMacSize;
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

static Bytes aes_encrypt(ByteView plain_text, ByteView key, ByteView iv) {
    assert(key.size() == kKeySize);
    assert(iv.size() == AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    auto _ = gsl::finally([ctx] { EVP_CIPHER_CTX_free(ctx); });

    int ok = EVP_EncryptInit(ctx, EVP_aes_128_ctr(), key.data(), iv.data());
    if (!ok)
        throw std::runtime_error("Failed to init AES encryption");

    Bytes::size_type max_size = (plain_text.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    Bytes cypher_text(max_size, 0);

    int cypher_len = 0;
    int remaining_len = 0;
    EVP_EncryptUpdate(ctx, cypher_text.data(), &cypher_len, plain_text.data(), static_cast<int>(plain_text.size()));
    EVP_EncryptFinal(ctx, cypher_text.data() + cypher_len, &remaining_len);

    cypher_text.resize(static_cast<Bytes::size_type>(cypher_len) + static_cast<Bytes::size_type>(remaining_len));
    return cypher_text;
}

static Bytes aes_decrypt(ByteView cipher_text, ByteView key, ByteView iv) {
    assert(key.size() == kKeySize);
    assert(iv.size() == AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    auto _ = gsl::finally([ctx] { EVP_CIPHER_CTX_free(ctx); });

    int ok = EVP_DecryptInit(ctx, EVP_aes_128_ctr(), key.data(), iv.data());
    if (!ok)
        throw std::runtime_error("Failed to init AES decryption");

    Bytes plain_text(cipher_text.size(), 0);

    int text_len = 0;
    int remaining_len = 0;
    EVP_DecryptUpdate(ctx, plain_text.data(), &text_len, cipher_text.data(), static_cast<int>(cipher_text.size()));
    EVP_DecryptFinal(ctx, plain_text.data() + text_len, &remaining_len);

    plain_text.resize(static_cast<Bytes::size_type>(text_len) + static_cast<Bytes::size_type>(remaining_len));
    return plain_text;
}

static Bytes sha256(ByteView data) {
    Bytes hash(32, 0);
    silkpre_sha256(hash.data(), data.data(), data.size(), /* use_cpu_extensions = */ false);
    return hash;
}

static Bytes hmac(ByteView key, ByteView data1, ByteView data2, ByteView data3) {
    assert(key.size() == 32);

    HMAC_CTX* ctx = HMAC_CTX_new();
    auto _ = gsl::finally([ctx] { HMAC_CTX_free(ctx); });

    int ok = HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), nullptr);
    if (!ok)
        throw std::runtime_error("Failed to init HMAC");

    HMAC_Update(ctx, data1.data(), data1.size());
    HMAC_Update(ctx, data2.data(), data2.size());
    HMAC_Update(ctx, data3.data(), data3.size());

    Bytes hash(HMAC_size(ctx), 0);
    HMAC_Final(ctx, hash.data(), nullptr);

    return hash;
}

Bytes EciesCipher::serialize_message(const Message& message) {
    secp256k1_pubkey public_key;
    assert(message.ephemeral_public_key.size() == sizeof(public_key.data));
    memcpy(public_key.data, message.ephemeral_public_key.data().data(), sizeof(public_key.data));

    SecP256K1Context ctx;
    Bytes key_data = ctx.serialize_public_key(&public_key, /* is_compressed = */ false);

    Bytes data;
    data.reserve(key_data.size()
            + message.iv.size()
            + message.cipher_text.size()
            + message.mac.size());
    data.append(key_data);
    data.append(message.iv);
    data.append(message.cipher_text);
    data.append(message.mac);
    return data;
}

EciesCipher::Message EciesCipher::deserialize_message(ByteView message_data) {
    const std::size_t key_size = SecP256K1Context::kPublicKeySizeUncompressed;
    const std::size_t iv_size = AES_BLOCK_SIZE;
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
