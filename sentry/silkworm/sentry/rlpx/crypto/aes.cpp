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

#include "aes.hpp"

#include <gsl/util>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <silkworm/sentry/common/random.hpp>

namespace silkworm::sentry::rlpx::crypto {

static const size_t kKeySize = 16;
extern const size_t kAESBlockSize = AES_BLOCK_SIZE;

Bytes aes_encrypt(ByteView plain_text, ByteView key, ByteView iv) {
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

Bytes aes_decrypt(ByteView cipher_text, ByteView key, ByteView iv) {
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

Bytes aes_make_iv() {
    return common::random_bytes(AES_BLOCK_SIZE);
}

size_t aes_round_up_to_block_size(size_t size) {
    return (size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
}

}  // namespace silkworm::sentry::rlpx::crypto
