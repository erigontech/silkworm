/*
* MDx Hash Function
* (C) 1999-2008 Jack Lloyd
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

#ifndef SILKWORM_CRYPTO_MDX_HASH_HPP_
#define SILKWORM_CRYPTO_MDX_HASH_HPP_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include <silkworm/common/base.hpp>

namespace silkworm::crypto {

/**
 * MDx Hash Function Base Class
 */
class MDx_HashFunction {
  public:
    /**
     * @param block_length is the number of bytes per block, which must
     *        be a power of 2 and at least 8.
     */
    explicit MDx_HashFunction(size_t block_length);

    Bytes process(ByteView in);

  protected:
    /**
     * Run the hash's compression function over a set of blocks
     * @param blocks the input
     * @param block_n the number of blocks
     */
    virtual void compress_n(const uint8_t blocks[], size_t block_n) = 0;

    virtual void clear();

    virtual Bytes return_out() = 0;

  private:
    void add_data(const uint8_t input[], size_t length);
    Bytes final_result();

    static constexpr uint8_t m_pad_char{0x80};
    static constexpr uint8_t m_counter_size{8};

    const uint8_t m_block_bits{0};

    uint64_t m_count{0};
    std::vector<uint8_t> m_buffer;
    size_t m_position{0};
};

}  // namespace silkworm::crypto

#endif  // SILKWORM_CRYPTO_MDX_HASH_HPP_
