// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecies_cipher.hpp"

#include <memory>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/secp256k1_context.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/rlpx/crypto/aes.hpp>
#include <silkworm/sentry/rlpx/crypto/hmac.hpp>
#include <silkworm/sentry/rlpx/crypto/sha256.hpp>

#include "ecies_cipher_error.hpp"

namespace silkworm::sentry::rlpx::auth {

static constexpr size_t kKeySize = 16;
static constexpr size_t kMacSize = 32;

static Bytes kdf(ByteView secret);
using namespace crypto;

Bytes EciesCipher::compute_shared_secret(PublicKeyView public_key_view, PrivateKeyView private_key) {
    secp256k1_pubkey public_key;
    SILKWORM_ASSERT(public_key_view.size() == sizeof(public_key.data));
    memcpy(public_key.data, public_key_view.data().data(), sizeof(public_key.data));

    Bytes shared_secret(kKeySize * 2, 0);
    SecP256K1Context ctx;
    bool ok = ctx.compute_ecdh_secret(shared_secret, &public_key, private_key);
    if (!ok) {
        throw EciesCipherError(EciesCipherErrorCode::kSharedSecretFailure, "EciesCipher::compute_shared_secret failed to ECDH-agree public and private key");
    }

    return shared_secret;
}

EciesCipher::Message EciesCipher::encrypt_message(
    ByteView plain_text,
    PublicKeyView public_key_view,
    ByteView mac_extra_data) {
    EccKeyPair ephemeral_key_pair;

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
        throw EciesCipherError(EciesCipherErrorCode::kInvalidMAC, "EciesCipher::decrypt_message: invalid MAC");
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
    SILKWORM_ASSERT(secret.size() == kKeySize * 2);
    Bytes data(sizeof(uint32_t), 0);
    endian::store_big_u32(data.data(), 1);
    data += secret;
    return sha256(data);
}

Bytes EciesCipher::serialize_message(const Message& message) {
    secp256k1_pubkey public_key;
    SILKWORM_ASSERT(message.ephemeral_public_key.size() == sizeof(public_key.data));
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
    const size_t key_size = SecP256K1Context::kPublicKeySizeUncompressed;
    const size_t iv_size = kAESBlockSize;
    const size_t mac_size = kMacSize;

    const size_t min_size = key_size + iv_size + mac_size;
    if (message_data.size() < min_size) {
        throw EciesCipherError(EciesCipherErrorCode::kDataSizeTooShort, "EciesCipher::deserialize_message: message data is too short");
    }
    const size_t cipher_text_size = message_data.size() - min_size;

    Bytes key_data{&message_data[0], key_size};
    Bytes iv{&message_data[key_size], iv_size};
    Bytes cipher_text{&message_data[key_size + iv_size], cipher_text_size};
    Bytes mac{&message_data[key_size + iv_size + cipher_text_size], mac_size};

    auto ephemeral_public_key = EccPublicKey::deserialize_std(key_data);

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
