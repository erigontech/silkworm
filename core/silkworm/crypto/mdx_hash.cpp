/*
* Merkle-Damgard Hash Function
* (C) 1999-2008,2018 Jack Lloyd
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

#include "mdx_hash.hpp"

#include <cassert>

#include <silkworm/common/endian.hpp>

namespace {

/**
 * Power of 2 test. T should be an unsigned integer type
 * @param arg an integer value
 * @return true iff arg is 2^n for some n > 0
 */
template <typename T>
inline constexpr bool is_power_of_2(T arg) {
    return (arg != 0) && (arg != 1) && ((arg & static_cast<T>(arg - 1)) == 0);
}

template <typename T>
constexpr uint8_t ceil_log2(T x) {
    static_assert(sizeof(T) < 32, "Abnormally large scalar");

    if (x >> (sizeof(T) * 8 - 1)) {
        return sizeof(T) * 8;
    }

    uint8_t result = 0;
    T compare = 1;

    while (compare < x) {
        compare <<= 1;
        ++result;
    }

    return result;
}

/**
 * Copy memory
 * @param out the destination array
 * @param in the source array
 * @param n the number of elements of in/out
 */
template <typename T>
inline constexpr void copy_mem(T* out, const T* in, size_t n) {
    static_assert(std::is_trivial<typename std::decay<T>::type>::value, "");

    // If n > 0 then args should be not null
    assert(n == 0 || (in != nullptr && out != nullptr));

    if (in != nullptr && out != nullptr && n > 0) {
        std::memmove(out, in, sizeof(T) * n);
    }
}

template <typename T, typename Alloc>
size_t buffer_insert(std::vector<T, Alloc>& buf, size_t buf_offset, const T input[], size_t input_length) {
    assert(buf_offset <= buf.size());
    const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
    if (to_copy > 0) {
        copy_mem(&buf[buf_offset], input, to_copy);
    }
    return to_copy;
}

/**
 * Zero out some bytes. Warning: use secure_scrub_memory instead if the
 * memory is about to be freed or otherwise the compiler thinks it can
 * elide the writes.
 *
 * @param ptr a pointer to memory to zero
 * @param bytes the number of bytes to zero in ptr
 */
inline constexpr void clear_bytes(void* ptr, size_t bytes) {
    if (bytes > 0) {
        std::memset(ptr, 0, bytes);
    }
}

/**
 * Zero memory before use. This simply calls memset and should not be
 * used in cases where the compiler cannot see the call as a
 * side-effecting operation (for example, if calling clear_mem before
 * deallocating memory, the compiler would be allowed to omit the call
 * to memset entirely under the as-if rule.)
 *
 * @param ptr a pointer to an array of Ts to zero
 * @param n the number of Ts pointed to by ptr
 */
template <typename T>
inline constexpr void clear_mem(T* ptr, size_t n) {
    clear_bytes(ptr, sizeof(T) * n);
}

/**
 * Zeroise the values; length remains unchanged
 * @param vec the vector to zeroise
 */
template <typename T, typename Alloc>
void zeroise(std::vector<T, Alloc>& vec) {
    clear_mem(vec.data(), vec.size());
}

}  // namespace

namespace silkworm::crypto {

/*
 * MDx_HashFunction Constructor
 */
MDx_HashFunction::MDx_HashFunction(size_t block_len) : m_block_bits(ceil_log2(block_len)), m_buffer(block_len) {
    assert(is_power_of_2(block_len));
    assert(3 <= m_block_bits && m_block_bits <= 16);
    assert(m_counter_size <= block_len);
}

Bytes MDx_HashFunction::process(ByteView in) {
    add_data(in.data(), in.size());
    return final_result();
}

/*
 * Clear memory of sensitive data
 */
void MDx_HashFunction::clear() {
    zeroise(m_buffer);
    m_count = m_position = 0;
}

/*
 * Update the hash
 */
void MDx_HashFunction::add_data(const uint8_t input[], size_t length) {
    const size_t block_len = size_t{1} << m_block_bits;

    m_count += length;

    if (m_position) {
        buffer_insert(m_buffer, m_position, input, length);

        if (m_position + length >= block_len) {
            compress_n(m_buffer.data(), 1);
            input += (block_len - m_position);
            length -= (block_len - m_position);
            m_position = 0;
        }
    }

    // Just in case the compiler can't figure out block_len is a power of 2
    const size_t full_blocks = length >> m_block_bits;
    const size_t remaining = length & (block_len - 1);

    if (full_blocks > 0) {
        compress_n(input, full_blocks);
    }

    buffer_insert(m_buffer, m_position, input + full_blocks * block_len, remaining);
    m_position += remaining;
}

/*
 * Finalize a hash
 */
Bytes MDx_HashFunction::final_result() {
    const size_t block_len = size_t{1} << m_block_bits;

    clear_mem(&m_buffer[m_position], block_len - m_position);
    m_buffer[m_position] = m_pad_char;

    if (m_position >= block_len - m_counter_size) {
        compress_n(m_buffer.data(), 1);
        zeroise(m_buffer);
    }

    assert(m_counter_size >= 8);

    const uint64_t bit_count = m_count * 8;

    endian::store_big_u64(&m_buffer[block_len - 8], bit_count);

    compress_n(m_buffer.data(), 1);
    return return_out();
}

}  // namespace silkworm::crypto
