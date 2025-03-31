// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

/*
 * Sux: Succinct data structures
 *
 * Copyright (C) 2019-2020 Emmanuel Esposito and Sebastiano Vigna
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

#include <cstdint>
#include <span>

namespace silkworm::snapshots::elias_fano {

//! Log2Q = Log2(Quantum)
inline constexpr uint64_t kLog2q = 8;
//! Q = Quantum
inline constexpr uint64_t kQ = 1 << kLog2q;  // 256
//! QMask = Quantum Mask
inline constexpr uint64_t kQMask = kQ - 1;
//! SuperQ = Super Quantum
inline constexpr uint64_t kSuperQ = 1 << 14;  // 16384
//! SuperQMask = SuperQuantum Mask
inline constexpr uint64_t kSuperQMask = kSuperQ - 1;
inline constexpr uint64_t kQPerSuperQ = kSuperQ / kQ;
inline constexpr uint64_t kSuperQSize16 = 1 + kQPerSuperQ / 4;
inline constexpr uint64_t kSuperQSize32 = 1 + kQPerSuperQ / 2;

template <class T, size_t Extent>
static void set(std::span<T, Extent> bits, const uint64_t pos) {
    bits[pos / 64] |= uint64_t{1} << (pos % 64);
}

//! This assumes that bits are set in monotonic order, so that we can skip the masking for the second word
template <class T, size_t Extent>
static void set_bits(std::span<T, Extent> bits, const uint64_t start, const uint64_t width, const uint64_t value) {
    const uint64_t shift = start & 63;
    const uint64_t mask = ((uint64_t{1} << width) - 1) << shift;
    const size_t idx64 = start >> 6;
    bits[idx64] = (bits[idx64] & ~mask) | (value << shift);
    if (shift + width > 64) {
        // Change two 64-bit words
        bits[idx64 + 1] = value >> (64 - shift);
    }
}

using silkworm::snapshots::encoding::Uint64Sequence;

}  // namespace silkworm::snapshots::elias_fano
