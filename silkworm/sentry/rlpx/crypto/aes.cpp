// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "aes.hpp"

#include <stdexcept>

#include <gsl/util>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <silkworm/sentry/common/random.hpp>

namespace silkworm::sentry::rlpx::crypto {

static constexpr size_t kKeySize128 = 16;
static constexpr size_t kKeySize256 = 32;
extern constexpr size_t kAESBlockSize = AES_BLOCK_SIZE;

AESCipher::AESCipher(ByteView key, std::optional<ByteView> iv, Direction direction) {
    SILKWORM_ASSERT(!iv || (iv->size() == kAESBlockSize));

    const EVP_CIPHER* mode{nullptr};
    switch (key.size()) {
        case kKeySize128:
            mode = iv ? EVP_aes_128_ctr() : EVP_aes_128_ecb();
            break;
        case kKeySize256:
            mode = iv ? EVP_aes_256_ctr() : EVP_aes_256_ecb();
            break;
        default:
            throw std::runtime_error("AESCipher: unsupported key size");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const unsigned char* iv_data = iv ? iv->data() : nullptr;

    int ok = 0;
    switch (direction) {
        case Direction::kEncrypt:
            ok = EVP_EncryptInit(ctx, mode, key.data(), iv_data);
            break;
        case Direction::kDecrypt:
            ok = EVP_DecryptInit(ctx, mode, key.data(), iv_data);
            break;
    }

    if (!ok) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AESCipher: failed to init");
    }

    ctx_ = ctx;
}

AESCipher::~AESCipher() {
    EVP_CIPHER_CTX_free(ctx_);
}

Bytes AESCipher::encrypt(ByteView plain_text) {
    if (plain_text.size() % kAESBlockSize)
        throw std::runtime_error("AESCipher: plain_text is not padded");

    Bytes cipher_text;
    cipher_text.resize(plain_text.size());

    int cipher_text_len = 0;
    EVP_EncryptUpdate(
        ctx_,
        cipher_text.data(),
        &cipher_text_len,
        plain_text.data(),
        static_cast<int>(plain_text.size()));

    cipher_text.resize(static_cast<Bytes::size_type>(cipher_text_len));
    return cipher_text;
}

Bytes AESCipher::decrypt(ByteView cipher_text) {
    Bytes plain_text;
    plain_text.resize(cipher_text.size());

    int plain_text_len = 0;
    EVP_DecryptUpdate(
        ctx_,
        plain_text.data(),
        &plain_text_len,
        cipher_text.data(),
        static_cast<int>(cipher_text.size()));

    plain_text.resize(static_cast<Bytes::size_type>(plain_text_len));
    return plain_text;
}

Bytes aes_encrypt(ByteView plain_text, ByteView key, ByteView iv) {
    AESCipher cipher{key, {iv}, AESCipher::Direction::kEncrypt};
    return cipher.encrypt(plain_text);
}

Bytes aes_decrypt(ByteView cipher_text, ByteView key, ByteView iv) {
    AESCipher cipher{key, {iv}, AESCipher::Direction::kDecrypt};
    return cipher.decrypt(cipher_text);
}

Bytes aes_make_iv() {
    return random_bytes(AES_BLOCK_SIZE);
}

size_t aes_round_up_to_block_size(size_t size) {
    return (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
}

}  // namespace silkworm::sentry::rlpx::crypto
