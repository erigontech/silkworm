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

#include <stdint.h>

#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace silkworm::endian {

uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    // TODO[C++20] static_assert(std::endian::order::native == std::endian::order::little);
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
#ifdef _MSC_VER
    return _byteswap_uint32(x);
#else
    return __builtin_bswap32(x);
#endif
}

uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    // TODO[C++20] static_assert(std::endian::order::native == std::endian::order::little);
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
#ifdef _MSC_VER
    return _byteswap_uint64(x);
#else
    return __builtin_bswap64(x);
#endif
}

}  // namespace silkworm::endian
