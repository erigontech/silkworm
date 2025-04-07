// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <gsl/pointers>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

using EVP_CIPHER_CTX = struct evp_cipher_ctx_st;

namespace silkworm::sentry::rlpx::crypto {

class AESCipher final {
  public:
    enum class Direction {
        kEncrypt,
        kDecrypt,
    };

    AESCipher(ByteView key, std::optional<ByteView> iv, Direction direction);
    ~AESCipher();

    Bytes encrypt(ByteView plain_text);
    Bytes decrypt(ByteView cipher_text);

  private:
    gsl::owner<EVP_CIPHER_CTX*> ctx_;
};

Bytes aes_encrypt(ByteView plain_text, ByteView key, ByteView iv);
Bytes aes_decrypt(ByteView cipher_text, ByteView key, ByteView iv);

Bytes aes_make_iv();

extern const size_t kAESBlockSize;

size_t aes_round_up_to_block_size(size_t size);

}  // namespace silkworm::sentry::rlpx::crypto
