/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_COMMON_ENDIAN_H_
#define SILKWORM_COMMON_ENDIAN_H_

#include <stdint.h>
#include <cstring>

#ifdef _WIN32
#include <intrin.h>
#define bswap32 _byteswap_ulong
#define bswap64 _byteswap_uint64

// On Windows assume little endian
#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN

#elif __APPLE__

#include <machine/endian.h>
#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

#else

#include <endian.h>

#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

#endif

namespace silkworm::endian {

#if __BYTE_ORDER == __LITTLE_ENDIAN

uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return bswap32(x);
}

uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return bswap64(x);
}

#else

uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return x;
}

uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return x;
}

#endif

}  // namespace silkworm::endian

#endif // !SILKWORM_COMMON_ENDIAN_H_
