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
 * Copyright (C) 2007-2020 Sebastiano Vigna
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

#include "../support/common.hpp"
#include "../util/Vector.hpp"
#include "SelectZero.hpp"

namespace sux::bits {

using namespace std;
using namespace sux;

/** A simple SelectZero implementation based on a two-level inventory,
 * and wired for approximately the same number of zeros and ones.
 *
 * The constructors of this class only store a reference
 * to a provided bit vector. Should the content of the
 * bit vector change, the results will be unpredictable.
 *
 * This implementation has been specifically developed to be used
 * with EliasFano.
 *
 * @tparam AT a type of memory allocation out of sux::util::AllocType.
 */

template <util::AllocType AT = util::AllocType::MALLOC>
class SimpleSelectZeroHalf {
  private:
    static const int log2_zeros_per_inventory = 10;
    static const int zeros_per_inventory = 1 << log2_zeros_per_inventory;
    static const uint64_t zeros_per_inventory_mask = zeros_per_inventory - 1;
    static const int log2_longwords_per_subinventory = 2;
    static const int longwords_per_subinventory = 1 << log2_longwords_per_subinventory;
    static const int log2_zeros_per_sub64 = log2_zeros_per_inventory - log2_longwords_per_subinventory;
    static const int zeros_per_sub64 = 1 << log2_zeros_per_sub64;
    static const uint64_t zeros_per_sub64_mask = zeros_per_sub64 - 1;
    static const int log2_zeros_per_sub16 = log2_zeros_per_sub64 - 2;
    static const int zeros_per_sub16 = 1 << log2_zeros_per_sub16;
    static const uint64_t zeros_per_sub16_mask = zeros_per_sub16 - 1;

    const uint64_t* bits;
    util::Vector<int64_t, AT> inventory;

    uint64_t num_words, inventory_size, num_zeros;

  public:
    SimpleSelectZeroHalf() {}

    /** Creates a new instance using a given bit vector.
     *
     * @param bits a bit vector of 64-bit words.
     * @param num_bits the length (in bits) of the bit vector.
     */

    SimpleSelectZeroHalf(const uint64_t* const bits, const uint64_t num_bits) : bits(bits) {
        num_words = (num_bits + 63) / 64;

        // Init rank/select structure
        uint64_t c = 0;
        for (uint64_t i = 0; i < num_words; i++) c += __builtin_popcountll(~bits[i]);
        num_zeros = c;

        if (num_bits % 64 != 0) c -= 64 - num_bits % 64;
        assert(c <= num_bits);

        inventory_size = (c + zeros_per_inventory - 1) / zeros_per_inventory;

#ifdef DEBUG
        printf("Number of bits: %" PRId64 " Number of zeros: %" PRId64 " (%.2f%%)\n", num_bits, c, (c * 100.0) / num_bits);

        printf("Ones per inventory: %d Ones per sub 64: %d sub 16: %d\n", zeros_per_inventory, zeros_per_sub64, zeros_per_sub16);
#endif

        inventory.size(inventory_size * (longwords_per_subinventory + 1) + 1);

        uint64_t d = 0;
        const uint64_t mask = zeros_per_inventory - 1;

        // First phase: we build an inventory for each one out of zeros_per_inventory.
        for (uint64_t i = 0; i < num_words; i++)
            for (int j = 0; j < 64; j++) {
                if (i * 64 + j >= num_bits) break;
                if (~bits[i] & 1ULL << j) {
                    if ((d & mask) == 0) inventory[(d >> log2_zeros_per_inventory) * (longwords_per_subinventory + 1)] = i * 64 + j;
                    d++;
                }
            }

        assert(c == d);
        inventory[inventory_size * (longwords_per_subinventory + 1)] = num_bits;

#ifdef DEBUG
        printf("Inventory entries filled: %" PRId64 "\n", inventory_size + 1);
#endif

        uint16_t* p16;
        int64_t* p64;

        d = 0;
        uint64_t exact = 0, start, span, inventory_index;
        int offset;

        for (uint64_t i = 0; i < num_words; i++)
            for (int j = 0; j < 64; j++) {
                if (i * 64 + j >= num_bits) break;
                if (~bits[i] & 1ULL << j) {
                    if ((d & mask) == 0) {
                        inventory_index = (d >> log2_zeros_per_inventory) * (longwords_per_subinventory + 1);
                        start = inventory[inventory_index];
                        span = inventory[inventory_index + longwords_per_subinventory + 1] - start;
                        if (span > (1 << 16)) inventory[inventory_index] = -inventory[inventory_index] - 1;
                        offset = 0;
                        p64 = &inventory[inventory_index + 1];
                        p16 = (uint16_t*)p64;
                    }

                    if (span < (1 << 16)) {
                        assert(i * 64 + j - start <= (1 << 16));
                        if ((d & zeros_per_sub16_mask) == 0) {
                            assert(offset < longwords_per_subinventory * 4);
                            p16[offset++] = i * 64 + j - start;
                        }
                    } else {
                        if ((d & zeros_per_sub64_mask) == 0) {
                            assert(offset < longwords_per_subinventory);
                            p64[offset++] = i * 64 + j - start;
                            exact++;
                        }
                    }

                    d++;
                }
            }

#ifdef DEBUG
            // printf("Exact entries: %" PRId64 "\n", exact);
            // printf("First inventories: %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 "\n", inventory[0], inventory[1], inventory[2],
            //       inventory[3]);
#endif
    }

    uint64_t selectZero(const uint64_t rank) {
#ifdef DEBUG
        printf("Selecting %" PRId64 "\n...", rank);
#endif
        assert(rank < num_zeros);

        const uint64_t inventory_index = rank >> log2_zeros_per_inventory;
        assert(inventory_index <= inventory_size);
        const int64_t* inventory_start = &inventory + (inventory_index << log2_longwords_per_subinventory) + inventory_index;

        const int64_t inventory_rank = *inventory_start;
        const int subrank = rank & zeros_per_inventory_mask;
#ifdef DEBUG
        printf("Rank: %" PRId64 " inventory index: %" PRId64 " inventory rank: %" PRId64 " subrank: %d\n", rank, inventory_index, inventory_rank, subrank);
#endif

        uint64_t start;
        int residual;

        if (inventory_rank >= 0) {
            start = inventory_rank + ((uint16_t*)(inventory_start + 1))[subrank >> log2_zeros_per_sub16];
            residual = subrank & zeros_per_sub16_mask;
        } else {
            assert((subrank >> log2_zeros_per_sub64) < longwords_per_subinventory);
            start = -inventory_rank - 1 + *(inventory_start + 1 + (subrank >> log2_zeros_per_sub64));
            residual = subrank & zeros_per_sub64_mask;
        }

#ifdef DEBUG
        printf("Differential; start: %" PRId64 " residual: %d\n", start, residual);
        if (residual == 0) puts("No residual; returning start");
#endif

        if (residual == 0) return start;

        uint64_t word_index = start / 64;
        uint64_t word = ~bits[word_index] & -1ULL << start % 64;

        for (;;) {
            const int bit_count = __builtin_popcountll(word);
            if (residual < bit_count) break;
            word = ~bits[++word_index];
            residual -= bit_count;
        }

        return word_index * 64 + select64(word, residual);
    }

    uint64_t selectZero(const uint64_t rank, uint64_t* const next) {
        const uint64_t s = selectZero(rank);
        int curr = s / 64;

        uint64_t window = ~bits[curr] & -1ULL << s;
        window &= window - 1;

        while (window == 0) window = ~bits[++curr];
        *next = curr * 64 + __builtin_ctzll(window);

        return s;
    }

    /** Returns an estimate of the size (in bits) of this structure. */
    size_t bitCount() const { return inventory.bitCount() - sizeof(inventory) * 8 + sizeof(*this) * 8; };
};

}  // namespace sux::bits
