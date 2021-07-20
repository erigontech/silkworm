/*
 * SHA-{224,256}
 * (C) 1999-2011 Jack Lloyd
 *     2007 FlexSecure GmbH
 *
 * Modified in 2021 by Andrew Ashikhmin for Silkworm.

Copyright (C) 1999-2021 The Botan Authors
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions, and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SILKWORM_CRYPTO_SHA256_HPP_
#define SILKWORM_CRYPTO_SHA256_HPP_

#include <vector>

#include <silkworm/crypto/mdx_hash.hpp>

namespace silkworm::crypto {

/**
 * SHA-256
 */
class SHA_256 final : public MDx_HashFunction {
  public:
    SHA_256() : MDx_HashFunction(64), m_digest(8) { clear(); }

    void clear() override;

    /*
     * Perform a SHA-256 compression. For internal use
     */
    static void compress_digest(std::vector<uint32_t>& digest, const uint8_t input[], size_t blocks);

  private:
    void compress_n(const uint8_t[], size_t blocks) override;
    Bytes return_out() override;

    std::vector<uint32_t> m_digest;
};

}  // namespace silkworm::crypto

#endif  // SILKWORM_CRYPTO_SHA256_HPP_
