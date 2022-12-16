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

/*
 * Sux: Succinct data structures
 *
 * Copyright (C) 2019-2020 Emmanuel Esposito, Stefano Marchini and Sebastiano Vigna
 *
 *  This library is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as published by the Free
 *  Software Foundation; either version 3 of the License, or (at your option)
 *  any later version.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * Under Section 7 of GPL version 3, you are granted additional permissions
 * described in the GCC Runtime Library Exception, version 3.1, as published by
 * the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License and a copy of
 * the GCC Runtime Library Exception along with this program; see the files
 * COPYING3 and COPYING.RUNTIME respectively.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <x86intrin.h>

#include <algorithm>
#include <cassert>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <memory>

#include <silkworm/common/assert.hpp>

// Macro stringification
#define __STRINGIFY(s) #s
#define STRINGIFY(s) __STRINGIFY(s)

// Explicit branch prediciton
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define ONES_STEP_4 (UINT64_C(0x1111111111111111))
#define ONES_STEP_8 (UINT64_C(0x0101010101010101))
#define ONES_STEP_9 (UINT64_C(1) << 0 | UINT64_C(1) << 9 | UINT64_C(1) << 18 | UINT64_C(1) << 27 | UINT64_C(1) << 36 | UINT64_C(1) << 45 | UINT64_C(1) << 54)
#define ONES_STEP_16 (UINT64_C(1) << 0 | UINT64_C(1) << 16 | UINT64_C(1) << 32 | UINT64_C(1) << 48)
#define ONES_STEP_32 (UINT64_C(0x0000000100000001))
#define MSBS_STEP_4 (UINT64_C(0x8) * ONES_STEP_4)
#define MSBS_STEP_8 (UINT64_C(0x80) * ONES_STEP_8)
#define MSBS_STEP_9 (UINT64_C(0x100) * ONES_STEP_9)
#define MSBS_STEP_16 (UINT64_C(0x8000) * ONES_STEP_16)
#define MSBS_STEP_32 (UINT64_C(0x8000000080000000))
#define ULEQ_STEP_9(x, y) (((((((y) | MSBS_STEP_9) - ((x) & ~MSBS_STEP_9)) | (x ^ y)) ^ (x & ~y)) & MSBS_STEP_9) >> 8)
#define ULEQ_STEP_16(x, y) (((((((y) | MSBS_STEP_16) - ((x) & ~MSBS_STEP_16)) | (x ^ y)) ^ (x & ~y)) & MSBS_STEP_16) >> 15)

namespace sux {

using std::memcpy;

using std::make_unique;
using std::unique_ptr;

using std::max;
using std::min;

using std::size_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::uint8_t;

/** Aliased unsigned integers
 *
 * Strict aliasing rule: it's illegal to access the same memory location with data of different
 * types. If you have two pointers T* and a U*, the compiler can assume they are not pointing the
 * same data. Accessing such a data invokes undefined behavior.
 *
 * GCC __may_alias__ attribute is basically the opposite of the C `restrict` keyword: it prevents
 * the compiler to make strict aliasing assumptions. With these aliased types is now valid to access
 * aliased pointers. [1]
 *
 * [1] https://gcc.gnu.org/onlinedocs/gcc-8.2.0/gcc/Common-Type-Attributes.html
 *
 */
///@{
using auint64_t = std::uint64_t __attribute__((__may_alias__));
using auint32_t = std::uint32_t __attribute__((__may_alias__));
using auint16_t = std::uint16_t __attribute__((__may_alias__));
using auint8_t = std::uint8_t __attribute__((__may_alias__));
///@}

// Bitmask array used in util::FenwickByteL and util::FenwickByteF
static constexpr uint64_t BYTE_MASK[] = {0x0ULL, 0xFFULL, 0xFFFFULL, 0xFFFFFFULL, 0xFFFFFFFFULL, 0xFFFFFFFFFFULL, 0xFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};

/** Static (i.e. computed in compile time) 1 + log2 rounded up. */
constexpr size_t ceil_log2_plus1(size_t n) { return ((n < 2) ? 1 : 1 + ceil_log2_plus1(n / 2)); }

/** log2 rounded up. */
int inline ceil_log2(const uint64_t x) { return x <= 2 ? static_cast<int>(x - 1) : 64 - __builtin_clzll(x - 1); }

/** Static round up to the next highest power of two.
 * @param v value to round up.
 *
 * The algorithm is a well known bit hack [1].
 *
 * [1] https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
 *
 */
constexpr uint64_t round_pow2(uint64_t v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    return v + 1;
}

// Required by select64
constexpr uint8_t kSelectInByte[2048] = {
    8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0, 4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    8, 8, 8, 1, 8, 2, 2, 1, 8, 3, 3, 1, 3, 2, 2, 1, 8, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 8, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1,
    8, 6, 6, 1, 6, 2, 2, 1, 6, 3, 3, 1, 3, 2, 2, 1, 6, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 6, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1,
    8, 7, 7, 1, 7, 2, 2, 1, 7, 3, 3, 1, 3, 2, 2, 1, 7, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 7, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1,
    7, 6, 6, 1, 6, 2, 2, 1, 6, 3, 3, 1, 3, 2, 2, 1, 6, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1, 6, 5, 5, 1, 5, 2, 2, 1, 5, 3, 3, 1, 3, 2, 2, 1, 5, 4, 4, 1, 4, 2, 2, 1, 4, 3, 3, 1, 3, 2, 2, 1,
    8, 8, 8, 8, 8, 8, 8, 2, 8, 8, 8, 3, 8, 3, 3, 2, 8, 8, 8, 4, 8, 4, 4, 2, 8, 4, 4, 3, 4, 3, 3, 2, 8, 8, 8, 5, 8, 5, 5, 2, 8, 5, 5, 3, 5, 3, 3, 2, 8, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2,
    8, 8, 8, 6, 8, 6, 6, 2, 8, 6, 6, 3, 6, 3, 3, 2, 8, 6, 6, 4, 6, 4, 4, 2, 6, 4, 4, 3, 4, 3, 3, 2, 8, 6, 6, 5, 6, 5, 5, 2, 6, 5, 5, 3, 5, 3, 3, 2, 6, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2,
    8, 8, 8, 7, 8, 7, 7, 2, 8, 7, 7, 3, 7, 3, 3, 2, 8, 7, 7, 4, 7, 4, 4, 2, 7, 4, 4, 3, 4, 3, 3, 2, 8, 7, 7, 5, 7, 5, 5, 2, 7, 5, 5, 3, 5, 3, 3, 2, 7, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2,
    8, 7, 7, 6, 7, 6, 6, 2, 7, 6, 6, 3, 6, 3, 3, 2, 7, 6, 6, 4, 6, 4, 4, 2, 6, 4, 4, 3, 4, 3, 3, 2, 7, 6, 6, 5, 6, 5, 5, 2, 6, 5, 5, 3, 5, 3, 3, 2, 6, 5, 5, 4, 5, 4, 4, 2, 5, 4, 4, 3, 4, 3, 3, 2,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 3, 8, 8, 8, 8, 8, 8, 8, 4, 8, 8, 8, 4, 8, 4, 4, 3, 8, 8, 8, 8, 8, 8, 8, 5, 8, 8, 8, 5, 8, 5, 5, 3, 8, 8, 8, 5, 8, 5, 5, 4, 8, 5, 5, 4, 5, 4, 4, 3,
    8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 3, 8, 8, 8, 6, 8, 6, 6, 4, 8, 6, 6, 4, 6, 4, 4, 3, 8, 8, 8, 6, 8, 6, 6, 5, 8, 6, 6, 5, 6, 5, 5, 3, 8, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 3, 8, 8, 8, 7, 8, 7, 7, 4, 8, 7, 7, 4, 7, 4, 4, 3, 8, 8, 8, 7, 8, 7, 7, 5, 8, 7, 7, 5, 7, 5, 5, 3, 8, 7, 7, 5, 7, 5, 5, 4, 7, 5, 5, 4, 5, 4, 4, 3,
    8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 3, 8, 7, 7, 6, 7, 6, 6, 4, 7, 6, 6, 4, 6, 4, 4, 3, 8, 7, 7, 6, 7, 6, 6, 5, 7, 6, 6, 5, 6, 5, 5, 3, 7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 5, 4, 4, 3,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 5, 8, 8, 8, 8, 8, 8, 8, 5, 8, 8, 8, 5, 8, 5, 5, 4,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 4, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 5, 8, 8, 8, 6, 8, 6, 6, 5, 8, 6, 6, 5, 6, 5, 5, 4,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 4, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 5, 8, 8, 8, 7, 8, 7, 7, 5, 8, 7, 7, 5, 7, 5, 5, 4,
    8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 4, 8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 5, 8, 7, 7, 6, 7, 6, 6, 5, 7, 6, 6, 5, 6, 5, 5, 4,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 5,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 8, 8, 8, 8, 6, 8, 8, 8, 6, 8, 6, 6, 5,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 5,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6, 8, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 5,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 6,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 8, 8, 8, 8, 7, 8, 8, 8, 7, 8, 7, 7, 6,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 7};

/** Find the index of the least significant 1-bit in a word.
 * @param word binary word.
 *
 * The Knuth's ruler function returns the number of trailing 0-bits in `word` starting from the least
 * significant position. It returns 0 when `word` is 2^0 and it returns 63 when it is 2^63.
 *
 * The behavior in zero is undefined.
 *
 */
inline int rho(uint64_t word) { return __builtin_ctzll(word); }

/** Find the index of the most significant 1-bit in a word.
 * @param word binary word.
 *
 * The Knuth's lambda function is the dual of the rho function.
 *
 * The behavior in zero is undefined.
 *
 */
inline int lambda(uint64_t word) { return 63 ^ __builtin_clzll(word); }

/** Find the index of the most significant 1-bit in a word.
 * @param word binary word.
 *
 * The Knuth's lambda function is the dual of the rho function.
 *
 * Returns -1 on input zero.
 *
 */
inline int lambda_safe(uint64_t word) { return word == 0 ? -1 : 63 ^ __builtin_clzll(word); }

/** Set to 0 the least significant 1-bit in a word.
 * @param word: binary word.
 *
 */
inline uint64_t clear_rho(uint64_t word) {
#ifdef __haswell__
    return _blsr_u64(word);
#else
    return word & (word - 1);
#endif
}

/** Bitmask where only the least significant 1-bit is set.
 * @param word: Binary word.
 *
 * Compute `2^rho(word)` for any `word` that is not zero.
 *
 */
inline uint64_t mask_rho(uint64_t word) { return word & (-word); }

/** Bitmask where only the most significant 1-bit is set.
 * @param word: Binary word.
 *
 * Undefined behavior when `word` is zero.
 *
 */
inline uint64_t mask_lambda(uint64_t word) { return 0x8000000000000000ULL >> __builtin_clzll(word); }

/** Generate a compact bitmask.
 * @param count  quantity of set bit.
 * @param pos starting position.
 *
 * This fucntion returns a bitmask with `count` 1-bits: every bit from `pos` to `pos+count` is set to
 * one. If `pos` is zero the bitmask has its `count` least significant bits setted to one.
 *
 */
inline uint64_t compact_bitmask(size_t count, size_t pos) { return static_cast<uint64_t>(-(count != 0ULL)) & (UINT64_MAX >> (64 - count)) << pos; }

//! Convert the number x which is assumed to be uniformly distributed over the range [0..2^64) to a number that is uniformly
//! distributed over the range [0..n), under assumption that n is less than 2^16
static inline uint64_t remap16(uint64_t x, uint64_t n) {
    SILKWORM_ASSERT(n < (1 << 16));
    static const int masklen = 48;
    static const uint64_t mask = (uint64_t(1) << masklen) - 1;
    return ((x & mask) * n) >> masklen;
}

static inline uint64_t remap128(uint64_t x, uint64_t n) {
#ifdef __SIZEOF_INT128__
    return static_cast<uint64_t>((static_cast<__uint128_t>(x) * static_cast<__uint128_t>(n)) >> 64);
#else
    // Less than 2^32 keys
    return (uint32_t)x * n >> 32;
#endif  // __SIZEOF_INT128__
}

/** Extract consecutives bits in a word.
 * @param word binary word.
 * @param from starting index (up to 63).
 * @param length length of the word (up to 64).
 *
 * Extracts from `word` the bits in the range `[from, from + length)` and returns them in the
 * least significant bits of the result.
 *
 */
inline uint64_t bitextract(const uint64_t* word, int from, int length) {
    if (likely((from + length) <= 64))
        return (word[0] >> from) & (-1ULL >> (64 - length));
    else
        return (word[0] >> from) | ((word[1] << (128 - from - length)) >> (64 - from));
}

inline uint64_t byteread(const void* const word, int length) {
    uint64_t ret;
    memcpy(&ret, word, sizeof(uint64_t));
    return ret & BYTE_MASK[length];
}

inline void bytewrite(void* const word, int length, uint64_t val) {
    uint64_t old;
    memcpy(&old, word, sizeof(uint64_t));

    old = (old & ~BYTE_MASK[length]) | (val & BYTE_MASK[length]);
    memcpy(word, &old, sizeof(uint64_t));
}

inline void bytewrite_inc(void* const word, uint64_t inc) {
    uint64_t value;
    memcpy(&value, word, sizeof(uint64_t));
    value += inc;
    memcpy(word, &value, sizeof(uint64_t));
}

inline uint64_t bitread(const void* const word, int from, int length) {
    uint64_t ret;
    memcpy(&ret, word, sizeof(uint64_t));

    if (likely((from + length) <= 64)) {
        return (ret >> from) & (-1ULL >> (64 - length));
    } else {
        uint64_t next;
        memcpy(&next, static_cast<const uint64_t*>(word) + 1, sizeof(uint64_t));
        return (ret >> from) | (next << (128 - from - length) >> (64 - length));
    }
}

inline void bitwrite(void* word, int from, int length, uint64_t val) {
    uint64_t old;
    memcpy(&old, word, sizeof(uint64_t));
    assert(length == 64 || val < (1ULL << length));

    if (likely((from + length) <= 64)) {
        const uint64_t mask = (-1ULL >> (64 - length)) << from;
        old = (old & ~mask) | (val << from);
        memcpy(word, &old, sizeof(uint64_t));
    } else {
        const uint64_t maskw = -1ULL << from;
        old = (old & ~maskw) | (val << from);
        memcpy(word, &old, sizeof(uint64_t));

        uint64_t next;
        memcpy(&next, static_cast<uint64_t*>(word) + 1, sizeof(uint64_t));
        const uint64_t maskb = -1ULL >> (128 - from - length);
        next = (next & ~maskb) | (val >> (64 - from));
        memcpy(static_cast<uint64_t*>(word) + 1, &next, sizeof(uint64_t));
    }
}

inline void bitwrite_inc(void* const word, int from, int length, uint64_t inc) {
    uint64_t value;
    memcpy(&value, word, sizeof(uint64_t));
    const uint64_t sum = (value >> from) + inc;
    const uint64_t carry = from > 0 ? sum >> (64 - from) : 0;

    if (likely((from + length) <= 64 || carry == 0)) {
        value += inc << from;
        memcpy(word, &value, sizeof(uint64_t));
    } else {
        value = from > 0 ? (value & (-1ULL >> (64 - from))) | (sum << from) : (sum << from);
        memcpy(word, &value, sizeof(uint64_t));

        uint64_t next;
        memcpy(&next, static_cast<uint64_t*>(word) + 1, sizeof(uint64_t));
        next += carry;
        memcpy(static_cast<uint64_t*>(word) + 1, &next, sizeof(uint64_t));
    }
}

/** Count the number of 1-bits in a word.
 * @param word binary word.
 *
 */
inline int nu(uint64_t word) { return __builtin_popcountll(word); }

/** Return a number rounded to the desired power of two multiple.
 * @param number value to round up.
 * @param multiple power of two to which you want to round `number`.
 *
 */
inline uint64_t mround(uint64_t number, uint64_t multiple) { return ((number - 1) | (multiple - 1)) + 1; }

/** Grandest grandparent parent of a node in the update tree.
 * @param j index of a node.
 * @param n size of the Fenwick tree.
 *
 */
inline size_t updroot(size_t j, size_t n) { return n & (SIZE_MAX << lambda((j ^ n) | mask_rho(j))); }

/** Returns the index of the k-th 1-bit in the 64-bit word x.
 * @param x 64-bit word.
 * @param k 0-based rank (`k = 0` returns the position of the first 1-bit).
 *
 * Uses the broadword selection algorithm by Vigna [1], improved by Gog and Petri [2] and Vigna [3].
 * Facebook's Folly implementation [4].
 *
 * [1] Sebastiano Vigna. Broadword Implementation of Rank/Select Queries. WEA, 2008
 *
 * [2] Simon Gog, Matthias Petri. Optimized succinct data structures for massive data. Softw. Pract.
 * Exper., 2014
 *
 * [3] Sebastiano Vigna. MG4J 5.2.1. http://mg4j.di.unimi.it/
 *
 * [4] Facebook Folly library: https://github.com/facebook/folly
 *
 */
inline uint64_t select64(uint64_t x, uint64_t k) {
#ifndef __haswell__
    constexpr uint64_t kOnesStep4 = 0x1111111111111111ULL;
    constexpr uint64_t kOnesStep8 = 0x0101010101010101ULL;
    constexpr uint64_t kLAMBDAsStep8 = 0x80ULL * kOnesStep8;

    auto s = x;
    s = s - ((s & 0xA * kOnesStep4) >> 1);
    s = (s & 0x3 * kOnesStep4) + ((s >> 2) & 0x3 * kOnesStep4);
    s = (s + (s >> 4)) & 0xF * kOnesStep8;
    uint64_t byteSums = s * kOnesStep8;

    uint64_t kStep8 = k * kOnesStep8;
    uint64_t geqKStep8 = (((kStep8 | kLAMBDAsStep8) - byteSums) & kLAMBDAsStep8);
    uint64_t place = static_cast<uint64_t>(nu(geqKStep8) * 8);
    uint64_t byteRank = k - (((byteSums << 8) >> place) & uint64_t(0xFF));
    return place + kSelectInByte[((x >> place) & 0xFF) | (byteRank << 8)];
#elif defined(__GNUC__) || defined(__clang__)
    // GCC and Clang won't inline the intrinsics.
    uint64_t result = uint64_t(1) << k;

    asm("pdep %1, %0, %0\n\t"
        "tzcnt %0, %0"
        : "+r"(result)
        : "r"(x));

    return result;
#else
    return _tzcnt_u64(_pdep_u64(1ULL << k, x));
#endif
}

/** Check if the architecture is big endian */
bool inline is_big_endian(void) {
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};

    return bint.c[0] == 1;
}

/** Check if the architecture is little endian */
bool inline is_little_endian(void) { return !is_big_endian(); }

/** Transform from big-endian to little-endian and vice versa
 * @param value integral value (sizeof 1, 2, 4 or 8 bytes)
 *
 */
template <class T>
typename std::enable_if<std::is_integral<T>::value, T>::type swap_endian(T value) {
    switch (sizeof(T)) {
        case 1:
            return value;
        case 2:
            return static_cast<uint16_t>(swap_endian<std::uint8_t>(value & 0x00ff) << 8) | static_cast<uint16_t>(swap_endian<std::uint8_t>(value >> 8));
        case 4:
            return static_cast<uint32_t>(swap_endian<std::uint16_t>(value & 0x0000ffff) << 16) | static_cast<uint32_t>(swap_endian<std::uint16_t>(value >> 16));
        case 8:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"
            return static_cast<uint64_t>(swap_endian<std::uint32_t>(value & 0x00000000ffffffffULL) << 32) | static_cast<uint64_t>(swap_endian<std::uint32_t>(value >> 32));
#pragma GCC diagnostic pop
        default:
            assert(false && "unsupported size");
    }
}

/** Host to network endianness converter
 * @param value integral value
 *
 */
template <class T>
T hton(T value) { return is_little_endian() ? swap_endian<T>(value) : value; }

/** Network to host endianness converter
 * @param value integral value
 *
 */
template <class T>
T ntoh(T value) { return hton(value); }

/** Little endian to host endianness converter
 * @param value integral value
 *
 */
template <class T>
T ltoh(T value) { return is_big_endian() ? swap_endian<T>(value) : value; }

/** Host endianness to little endian converter
 * @param value integral value
 *
 */
template <class T>
T htol(T value) { return ltoh(value); }

}  // namespace sux
