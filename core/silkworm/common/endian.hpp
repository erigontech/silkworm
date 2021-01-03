/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_ENDIAN_HPP_
#define SILKWORM_COMMON_ENDIAN_HPP_

#include <stdint.h>

#include <cstring>

#ifdef _WIN32

#include <intrin.h>
#define SILKWORM_BSWAP32 _byteswap_ulong
#define SILKWORM_BSWAP64 _byteswap_uint64

// On Windows assume little endian
#define SILKWORM_LITTLE_ENDIAN 1234
#define SILKWORM_BIG_ENDIAN 4321
#define SILKWORM_BYTE_ORDER SILKWORM_LITTLE_ENDIAN

#elif __APPLE__

#include <machine/endian.h>
#define SILKWORM_BSWAP32 __builtin_bswap32
#define SILKWORM_BSWAP64 __builtin_bswap64

#define SILKWORM_LITTLE_ENDIAN LITTLE_ENDIAN
#define SILKWORM_BIG_ENDIAN BIG_ENDIAN
#define SILKWORM_BYTE_ORDER BYTE_ORDER

#else

#include <endian.h>
#define SILKWORM_BSWAP32 __builtin_bswap32
#define SILKWORM_BSWAP64 __builtin_bswap64

#define SILKWORM_LITTLE_ENDIAN __LITTLE_ENDIAN
#define SILKWORM_BIG_ENDIAN __BIG_ENDIAN
#define SILKWORM_BYTE_ORDER __BYTE_ORDER

#endif

namespace silkworm::endian {

inline uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
#if SILKWORM_BYTE_ORDER == SILKWORM_BIG_ENDIAN
    return x;
#elif SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
    return SILKWORM_BSWAP32(x);
#else
#error byte order not supported
#endif
}

inline uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
#if SILKWORM_BYTE_ORDER == SILKWORM_BIG_ENDIAN
    return x;
#elif SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN
    return SILKWORM_BSWAP64(x);
#else
#error byte order not supported
#endif
}

}  // namespace silkworm::endian

#endif  // SILKWORM_COMMON_ENDIAN_HPP_
