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
#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace silkworm {

//! \brief Returns the number of one bits in x.
inline uint16_t popcount_16(uint16_t x) {
#ifdef _MSC_VER
    return x ? __popcnt16(x) : 0;
#else
    return static_cast<uint16_t>(x ? __builtin_popcount(x) : 0);
#endif
}

//! \brief Returns the number of leading zero bits in x; the result is 16 for x == 0.
inline uint16_t clz_16(uint16_t x) {
#ifdef _MSC_VER
    static unsigned long index{0};
    if (!x || !_BitScanReverse(&index, static_cast<uint32_t>(x))) {
        return static_cast<uint16_t>(16);
    }
    return static_cast<uint16_t>(31u - (index + 16));
#else
    if (!x) {
        return 16;
    }
    return static_cast<uint16_t>(__builtin_clz(x)) - 16u;
#endif
}

//! \brief Returns the number of trailing zero bits in x; the result is 16 for x == 0.
inline uint16_t ctz_16(uint16_t x) {
#ifdef _MSC_VER
    static unsigned long index{0};
    if (!x || !_BitScanForward(&index, static_cast<uint32_t>(x))) {
        return static_cast<uint16_t>(16);
    }
    return static_cast<uint16_t>(index);
#else
    if (!x) {
        return 16;
    }
    return static_cast<uint16_t>(__builtin_ctz(x));
#endif
}

//! \brief Returns the minimum number of bits required to represent x; the result is 0 for x == 0.
inline uint16_t bitlen_16(uint16_t x) { return static_cast<uint16_t>(x ? 16 - clz_16(x) : 0); }

}  // namespace silkworm

