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

#pragma once

#include <cstdint>
#include <optional>

#include <gsl/pointers>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

using EVP_CIPHER_CTX = struct evp_cipher_ctx_st;

namespace silkworm::sentry::rlpx::crypto {

class AESCipher final {
  public:
    enum class Direction : uint8_t {
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
