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

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#include "murmur_hash3.hpp"

#include <cstddef>

namespace silkworm::snapshots::encoding {

// Platform-specific functions and macros

// Microsoft Visual Studio
#if defined(_MSC_VER)

#define FORCE_INLINE __forceinline

#include <stdlib.h>

#define ROTL64(x, y) _rotl64(x, y)

#define BIG_CONSTANT(x) (x)

// Other compilers

#else  // defined(_MSC_VER)
#define FORCE_INLINE inline __attribute__((always_inline))

inline uint64_t rotl64(uint64_t x, int8_t r) {
    return (x << r) | (x >> (64 - r));
}

#define ROTL64(x, y) rotl64(x, y)
#define BIG_CONSTANT(x) (x##LLU)
#endif  // !defined(_MSC_VER)

// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

FORCE_INLINE uint64_t getblock64(const uint64_t* p, size_t i) {
    return p[i];
}

// Finalization mix - force all bits of a hash block to avalanche

FORCE_INLINE uint64_t fmix64(uint64_t k) {
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}

void murmur_hash3_x64_128(const void* key, const uint64_t len,
                          const uint32_t seed, void* out) {
    const auto* data = reinterpret_cast<const uint8_t*>(key);
    const size_t num_blocks = len / 16;

    uint64_t h1 = seed;
    uint64_t h2 = seed;

    const uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
    const uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

    //----------
    // body

    const auto* blocks = reinterpret_cast<const uint64_t*>(data);

    for (size_t i{0}; i < num_blocks; ++i) {
        uint64_t k1 = getblock64(blocks, i * 2 + 0);
        uint64_t k2 = getblock64(blocks, i * 2 + 1);

        k1 *= c1;
        k1 = ROTL64(k1, 31);
        k1 *= c2;
        h1 ^= k1;

        h1 = ROTL64(h1, 27);
        h1 += h2;
        h1 = h1 * 5 + 0x52dce729;

        k2 *= c2;
        k2 = ROTL64(k2, 33);
        k2 *= c1;
        h2 ^= k2;

        h2 = ROTL64(h2, 31);
        h2 += h1;
        h2 = h2 * 5 + 0x38495ab5;
    }

    //----------
    // tail

    const auto* tail = reinterpret_cast<const uint8_t*>(data + num_blocks * 16);

    uint64_t k1 = 0;
    uint64_t k2 = 0;

    switch (len & 15) {
        case 15:
            k2 ^= static_cast<uint64_t>(tail[14]) << 48;
            [[fallthrough]];
        case 14:
            k2 ^= static_cast<uint64_t>(tail[13]) << 40;
            [[fallthrough]];
        case 13:
            k2 ^= static_cast<uint64_t>(tail[12]) << 32;
            [[fallthrough]];
        case 12:
            k2 ^= static_cast<uint64_t>(tail[11]) << 24;
            [[fallthrough]];
        case 11:
            k2 ^= static_cast<uint64_t>(tail[10]) << 16;
            [[fallthrough]];
        case 10:
            k2 ^= static_cast<uint64_t>(tail[9]) << 8;
            [[fallthrough]];
        case 9:
            k2 ^= static_cast<uint64_t>(tail[8]) << 0;
            k2 *= c2;
            k2 = ROTL64(k2, 33);
            k2 *= c1;
            h2 ^= k2;

            [[fallthrough]];
        case 8:
            k1 ^= static_cast<uint64_t>(tail[7]) << 56;
            [[fallthrough]];
        case 7:
            k1 ^= static_cast<uint64_t>(tail[6]) << 48;
            [[fallthrough]];
        case 6:
            k1 ^= static_cast<uint64_t>(tail[5]) << 40;
            [[fallthrough]];
        case 5:
            k1 ^= static_cast<uint64_t>(tail[4]) << 32;
            [[fallthrough]];
        case 4:
            k1 ^= static_cast<uint64_t>(tail[3]) << 24;
            [[fallthrough]];
        case 3:
            k1 ^= static_cast<uint64_t>(tail[2]) << 16;
            [[fallthrough]];
        case 2:
            k1 ^= static_cast<uint64_t>(tail[1]) << 8;
            [[fallthrough]];
        case 1:
            k1 ^= static_cast<uint64_t>(tail[0]) << 0;
            k1 *= c1;
            k1 = ROTL64(k1, 31);
            k1 *= c2;
            h1 ^= k1;
            [[fallthrough]];
        default:
            break;  // do nothing
    }

    //----------
    // finalization

    h1 ^= len;
    h2 ^= len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;

    reinterpret_cast<uint64_t*>(out)[0] = h1;
    reinterpret_cast<uint64_t*>(out)[1] = h2;
}

}  // namespace silkworm::snapshots::encoding
