/*
   Copyright 2024 The Silkworm Authors

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

#if (defined(_MSC_VER) && _MSC_VER >= 1928)
#include <intrin.h>
inline int __builtin_clz(unsigned int x) {
    unsigned long index;
    return int(_BitScanReverse(&index, (unsigned long)x) ? 31 - index : 32);
}
inline int __builtin_clzl(unsigned long x) {
    return __builtin_clz((unsigned int)x);
}
#if defined(_M_IX86) || defined(_M_ARM) || defined(_M_ARM64)
inline int __builtin_clzll(unsigned long long x) {
    if (x == 0) {
        return 64;
    }
    unsigned int msb = (unsigned int)(x >> 32);
    unsigned int lsb = (unsigned int)x;
    return (msb != 0) ? __builtin_clz(msb) : 32 + __builtin_clz(lsb);
}
#else
inline int __builtin_clzll(unsigned long long x) {
    unsigned long index;
    return int(_BitScanReverse64(&index, x) ? 63 - index : 64);
}
#endif
inline int __builtin_ctz(unsigned int x) {
    unsigned long index;
    return int(_BitScanForward(&index, (unsigned long)x) ? index : 32);
}
inline int __builtin_ctzl(unsigned long x) {
    return __builtin_ctz((unsigned int)x);
}
#if defined(_M_IX86) || defined(_M_ARM) || defined(_M_ARM64)
inline int __builtin_ctzll(unsigned long long x) {
    unsigned long index;
    unsigned int msb = (unsigned int)(x >> 32);
    unsigned int lsb = (unsigned int)x;
    if (lsb != 0) {
        return (int)(_BitScanForward(&index, lsb) ? index : 64);
    } else {
        return (int)(_BitScanForward(&index, msb) ? index + 32 : 64);
    }
}
#else
inline int __builtin_ctzll(unsigned long long x) {
    unsigned long index;
    return int(_BitScanForward64(&index, x) ? index : 64);
}
#endif

inline int __builtin_ffs(int x) {
    unsigned long index;
    return int(_BitScanForward(&index, (unsigned long)x) ? index + 1 : 0);
}
inline int __builtin_ffsl(long x) {
    return __builtin_ffs(int(x));
}
#if defined(_M_IX86) || defined(_M_ARM) || defined(_M_ARM64)
inline int __builtin_ffsll(long long x) {
    int ctzll = __builtin_ctzll((unsigned long long)x);
    return ctzll != 64 ? ctzll + 1 : 0;
}
#else
inline int __builtin_ffsll(long long x) {
    unsigned long index;
    return int(_BitScanForward64(&index, (unsigned long long)x) ? index + 1 : 0);
}
inline int __builtin_popcount(unsigned int x) {
    return int(__popcnt(x));
}

inline int __builtin_popcountl(unsigned long x) {
    static_assert(sizeof(x) == 4, "");
    return int(__popcnt(x));
}
#endif

#if defined(_M_IX86)
inline int __builtin_popcountll(unsigned long long x) {
    return int(__popcnt((unsigned int)(x >> 32))) +
           int(__popcnt((unsigned int)x));
}
#elif defined(_M_X64)
inline int __builtin_popcountll(unsigned long long x) {
    return int(__popcnt64(x));
}
#endif
#endif
