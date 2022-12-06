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
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

#include "../support/common.hpp"
#include "../util/Vector.hpp"

#ifndef LOG2Q
#define LOG2Q 8
#endif

namespace sux::function {

using namespace sux;
using namespace sux::util;

/** A double Elias-Fano list.
 *
 * This class exists solely to implement RecSplit.
 * @tparam AT a type of memory allocation out of util::AllocType.
 */

template <util::AllocType AT = util::AllocType::MALLOC>
class DoubleEF {
  private:
    static constexpr uint64_t log2q = LOG2Q;
    static constexpr uint64_t q = 1 << log2q;
    static constexpr uint64_t q_mask = q - 1;
    static constexpr uint64_t super_q = 1 << 14;
    static constexpr uint64_t super_q_mask = super_q - 1;
    static constexpr uint64_t q_per_super_q = super_q / q;
    static constexpr uint64_t super_q_size = 1 + q_per_super_q / 4;
    Vector<uint64_t, AT> lower_bits, upper_bits_position, upper_bits_cum_keys, jump;
    uint64_t lower_bits_mask_cum_keys, lower_bits_mask_position;

    uint64_t num_buckets, u_cum_keys, u_position;
    uint64_t l_position, l_cum_keys;
    int64_t cum_keys_min_delta, min_diff;
    uint64_t bits_per_key_fixed_point;

    __inline static void set(util::Vector<uint64_t, AT>& bits, const uint64_t pos) { bits[pos / 64] |= 1ULL << pos % 64; }

    __inline static void set_bits(util::Vector<uint64_t, AT>& bits, const uint64_t start, const int width, const uint64_t value) {
        const uint64_t mask = ((UINT64_C(1) << width) - 1) << start % 8;
        uint64_t t;
        memcpy(&t, reinterpret_cast<uint8_t*>(&bits) + start / 8, 8);
        t = (t & ~mask) | value << start % 8;
        memcpy(reinterpret_cast<uint8_t*>(&bits) + start / 8, &t, 8);
    }

    __inline size_t lower_bits_size_words() const { return ((num_buckets + 1) * (l_cum_keys + l_position) + 63) / 64 + 1; }

    __inline size_t cum_keys_size_words() const { return (num_buckets + 1 + (u_cum_keys >> l_cum_keys) + 63) / 64; }

    __inline size_t position_size_words() const { return (num_buckets + 1 + (u_position >> l_position) + 63) / 64; }

    __inline size_t jump_size_words() const {
        size_t size = (num_buckets / super_q) * super_q_size * 2;                                         // Whole blocks
        if (num_buckets % super_q != 0) size += (1 + ((num_buckets % super_q + q - 1) / q + 3) / 4) * 2;  // Partial block
        return size;
    }

    friend std::ostream& operator<<(std::ostream& os, const DoubleEF<AT>& ef) {
        os.write(reinterpret_cast<char*>(&ef.num_buckets), sizeof(ef.num_buckets));
        os.write(reinterpret_cast<char*>(&ef.u_cum_keys), sizeof(ef.u_cum_keys));
        os.write(reinterpret_cast<char*>(&ef.u_position), sizeof(ef.u_position));
        os.write(reinterpret_cast<char*>(&ef.cum_keys_min_delta), sizeof(ef.cum_keys_min_delta));
        os.write(reinterpret_cast<char*>(&ef.min_diff), sizeof(ef.min_diff));
        os.write(reinterpret_cast<char*>(&ef.bits_per_key_fixed_point), sizeof(ef.bits_per_key_fixed_point));

        os << ef.lower_bits;
        os << ef.upper_bits_cum_keys;
        os << ef.upper_bits_position;
        os << ef.jump;
        return os;
    }

    friend std::istream& operator>>(std::istream& is, DoubleEF<AT>& ef) {
        is.read(reinterpret_cast<char*>(&ef.num_buckets), sizeof(ef.num_buckets));
        is.read(reinterpret_cast<char*>(&ef.u_cum_keys), sizeof(ef.u_cum_keys));
        is.read(reinterpret_cast<char*>(&ef.u_position), sizeof(ef.u_position));
        is.read(reinterpret_cast<char*>(&ef.cum_keys_min_delta), sizeof(ef.cum_keys_min_delta));
        is.read(reinterpret_cast<char*>(&ef.min_diff), sizeof(ef.min_diff));
        is.read(reinterpret_cast<char*>(&ef.bits_per_key_fixed_point), sizeof(ef.bits_per_key_fixed_point));

        ef.l_position = ef.u_position / (ef.num_buckets + 1) == 0 ? 0 : lambda(ef.u_position / (ef.num_buckets + 1));
        ef.l_cum_keys = ef.u_cum_keys / (ef.num_buckets + 1) == 0 ? 0 : lambda(ef.u_cum_keys / (ef.num_buckets + 1));
        assert(ef.l_cum_keys * 2 + ef.l_position <= 56);

        ef.lower_bits_mask_cum_keys = (UINT64_C(1) << ef.l_cum_keys) - 1;
        ef.lower_bits_mask_position = (UINT64_C(1) << ef.l_position) - 1;

        is >> ef.lower_bits;
        is >> ef.upper_bits_cum_keys;
        is >> ef.upper_bits_position;
        is >> ef.jump;
        return is;
    }

  public:
    DoubleEF() {}

    DoubleEF(const std::vector<uint64_t>& cum_keys, const std::vector<uint64_t>& position) {
        assert(cum_keys.size() == position.size());
        num_buckets = cum_keys.size() - 1;

        bits_per_key_fixed_point = (uint64_t(1) << 20) * (position[num_buckets] / static_cast<double>(cum_keys[num_buckets]));

        min_diff = std::numeric_limits<int64_t>::max() / 2;
        cum_keys_min_delta = std::numeric_limits<int64_t>::max() / 2;
        int64_t prev_bucket_bits = 0;
        for (size_t i = 1; i <= num_buckets; ++i) {
            const int64_t nkeys_delta = cum_keys[i] - cum_keys[i - 1];
            cum_keys_min_delta = min(cum_keys_min_delta, nkeys_delta);
            const int64_t bucket_bits = int64_t(position[i]) - int64_t(bits_per_key_fixed_point * cum_keys[i] >> 20);
            min_diff = min(min_diff, bucket_bits - prev_bucket_bits);
            prev_bucket_bits = bucket_bits;
        }

        u_position = int64_t(position[num_buckets]) - int64_t(bits_per_key_fixed_point * cum_keys[num_buckets] >> 20) - int64_t(num_buckets * min_diff) + 1;
        l_position = u_position / (num_buckets + 1) == 0 ? 0 : lambda(u_position / (num_buckets + 1));
        u_cum_keys = cum_keys[num_buckets] - num_buckets * cum_keys_min_delta + 1;
        l_cum_keys = u_cum_keys / (num_buckets + 1) == 0 ? 0 : lambda(u_cum_keys / (num_buckets + 1));
        assert(l_cum_keys * 2 + l_position <= 56);  // To be able to perform a single unaligned read

#ifdef MORESTATS
        printf("Elias-Fano l (cumulative): %d\n", l_cum_keys);
        printf("Elias-Fano l (positions): %d\n", l_position);
        printf("Elias-Fano u (cumulative): %lld\n", u_cum_keys);
        printf("Elias-Fano u (positions): %lld\n", u_position);
#endif

        lower_bits_mask_cum_keys = (UINT64_C(1) << l_cum_keys) - 1;
        lower_bits_mask_position = (UINT64_C(1) << l_position) - 1;

        const uint64_t words_lower_bits = lower_bits_size_words();
        lower_bits.size(words_lower_bits);
        const uint64_t words_cum_keys = cum_keys_size_words();
        upper_bits_cum_keys.size(words_cum_keys);
        const uint64_t words_position = position_size_words();
        upper_bits_position.size(words_position);

        for (uint64_t i = 0, cum_delta = 0, bit_delta = 0; i <= num_buckets; i++, cum_delta += cum_keys_min_delta, bit_delta += min_diff) {
            if (l_cum_keys != 0) set_bits(lower_bits, i * (l_cum_keys + l_position), l_cum_keys, (cum_keys[i] - cum_delta) & lower_bits_mask_cum_keys);
            set(upper_bits_cum_keys, ((cum_keys[i] - cum_delta) >> l_cum_keys) + i);

            const auto pval = int64_t(position[i]) - int64_t(bits_per_key_fixed_point * cum_keys[i] >> 20);
            if (l_position != 0) set_bits(lower_bits, i * (l_cum_keys + l_position) + l_cum_keys, l_position, (pval - bit_delta) & lower_bits_mask_position);
            set(upper_bits_position, ((pval - bit_delta) >> l_position) + i);
        }

        const uint64_t jump_words = jump_size_words();
        jump.size(jump_words);
        if (jump_words == 0) return;

        for (uint64_t i = 0, c = 0, last_super_q = 0; i < words_cum_keys; i++) {
            for (int b = 0; b < 64; b++) {
                if (upper_bits_cum_keys[i] & UINT64_C(1) << b) {
                    if ((c & super_q_mask) == 0) jump[(c / super_q) * (super_q_size * 2)] = last_super_q = i * 64 + b;
                    if ((c & q_mask) == 0) {
                        const uint64_t offset = i * 64 + b - last_super_q;
                        if (offset >= (1 << 16)) abort();
                        (reinterpret_cast<uint16_t*>(&jump + (c / super_q) * (super_q_size * 2) + 2))[2 * ((c % super_q) / q)] = offset;
                    }
                    c++;
                }
            }
        }

        for (uint64_t i = 0, c = 0, last_super_q = 0; i < words_position; i++) {
            for (int b = 0; b < 64; b++) {
                if (upper_bits_position[i] & UINT64_C(1) << b) {
                    if ((c & super_q_mask) == 0) jump[(c / super_q) * (super_q_size * 2) + 1] = last_super_q = i * 64 + b;
                    if ((c & q_mask) == 0) {
                        const uint64_t offset = i * 64 + b - last_super_q;
                        if (offset >= (1 << 16)) abort();
                        (reinterpret_cast<uint16_t*>(&jump + (c / super_q) * (super_q_size * 2) + 2))[2 * ((c % super_q) / q) + 1] = offset;
                    }
                    c++;
                }
            }
        }

#ifndef NDEBUG
        for (uint64_t i = 0; i < num_buckets; i++) {
            uint64_t x, x2, y;

            get(i, x, x2, y);
            assert(x == cum_keys[i]);
            assert(x2 == cum_keys[i + 1]);
            assert(y == position[i]);

            get(i, x, y);
            assert(x == cum_keys[i]);
            assert(y == position[i]);
        }
#endif
    }

    void get(const uint64_t i, uint64_t& cum_keys, uint64_t& cum_keys_next, uint64_t& position) {
        const uint64_t pos_lower = i * (l_cum_keys + l_position);
        uint64_t lower;
        memcpy(&lower, reinterpret_cast<uint8_t*>(&lower_bits) + pos_lower / 8, 8);
        lower >>= pos_lower % 8;

        const uint64_t jump_super_q = (i / super_q) * super_q_size * 2;
        const uint64_t jump_inside_super_q = (i % super_q) / q;
        const uint64_t jump_cum_keys = jump[jump_super_q] + (reinterpret_cast<uint16_t*>(&jump + jump_super_q + 2))[2 * jump_inside_super_q];
        const uint64_t jump_position = jump[jump_super_q + 1] + (reinterpret_cast<uint16_t*>(&jump + jump_super_q + 2))[2 * jump_inside_super_q + 1];

        uint64_t curr_word_cum_keys = jump_cum_keys / 64;
        uint64_t curr_word_position = jump_position / 64;
        uint64_t window_cum_keys = upper_bits_cum_keys[curr_word_cum_keys] & UINT64_C(-1) << jump_cum_keys % 64;
        uint64_t window_position = upper_bits_position[curr_word_position] & UINT64_C(-1) << jump_position % 64;
        uint64_t delta_cum_keys = i & q_mask;
        uint64_t delta_position = i & q_mask;

        for (uint64_t bit_count; (bit_count = nu(window_cum_keys)) <= delta_cum_keys; delta_cum_keys -= bit_count) window_cum_keys = upper_bits_cum_keys[++curr_word_cum_keys];
        for (uint64_t bit_count; (bit_count = nu(window_position)) <= delta_position; delta_position -= bit_count) window_position = upper_bits_position[++curr_word_position];

        const uint64_t select_cum_keys = select64(window_cum_keys, delta_cum_keys);
        const int64_t cum_delta = i * cum_keys_min_delta;
        cum_keys = ((curr_word_cum_keys * 64 + select_cum_keys - i) << l_cum_keys | (lower & lower_bits_mask_cum_keys)) + cum_delta;

        lower >>= l_cum_keys;
        const int64_t bit_delta = i * min_diff;
        position = ((curr_word_position * 64 + select64(window_position, delta_position) - i) << l_position | (lower & lower_bits_mask_position)) + bit_delta +
                   int64_t(bits_per_key_fixed_point * cum_keys >> 20);

        window_cum_keys &= (-1ULL << select_cum_keys) << 1;
        while (window_cum_keys == 0) window_cum_keys = upper_bits_cum_keys[++curr_word_cum_keys];

        lower >>= l_position;
        cum_keys_next = ((curr_word_cum_keys * 64 + rho(window_cum_keys) - i - 1) << l_cum_keys | (lower & lower_bits_mask_cum_keys)) + cum_delta + cum_keys_min_delta;
    }

    void get(const uint64_t i, uint64_t& cum_keys, uint64_t& position) {
        const uint64_t pos_lower = i * (l_cum_keys + l_position);
        uint64_t lower;
        memcpy(&lower, reinterpret_cast<uint8_t*>(&lower_bits) + pos_lower / 8, 8);
        lower >>= pos_lower % 8;

        const uint64_t jump_super_q = (i / super_q) * super_q_size * 2;
        const uint64_t jump_inside_super_q = (i % super_q) / q;
        const uint64_t jump_cum_keys = jump[jump_super_q] + (reinterpret_cast<uint16_t*>(&jump + jump_super_q + 2))[2 * jump_inside_super_q];
        const uint64_t jump_position = jump[jump_super_q + 1] + (reinterpret_cast<uint16_t*>(&jump + jump_super_q + 2))[2 * jump_inside_super_q + 1];

        uint64_t curr_word_cum_keys = jump_cum_keys / 64;
        uint64_t curr_word_position = jump_position / 64;
        uint64_t window_cum_keys = upper_bits_cum_keys[curr_word_cum_keys] & UINT64_C(-1) << jump_cum_keys % 64;
        uint64_t window_position = upper_bits_position[curr_word_position] & UINT64_C(-1) << jump_position % 64;
        uint64_t delta_cum_keys = i & q_mask;
        uint64_t delta_position = i & q_mask;

        for (uint64_t bit_count; (bit_count = nu(window_cum_keys)) <= delta_cum_keys; delta_cum_keys -= bit_count) window_cum_keys = upper_bits_cum_keys[++curr_word_cum_keys];
        for (uint64_t bit_count; (bit_count = nu(window_position)) <= delta_position; delta_position -= bit_count) window_position = upper_bits_position[++curr_word_position];

        const uint64_t select_cum_keys = select64(window_cum_keys, delta_cum_keys);
        const size_t cum_delta = i * cum_keys_min_delta;
        cum_keys = ((curr_word_cum_keys * 64 + select_cum_keys - i) << l_cum_keys | (lower & lower_bits_mask_cum_keys)) + cum_delta;

        lower >>= l_cum_keys;
        const int64_t bit_delta = i * min_diff;
        position = ((curr_word_position * 64 + select64(window_position, delta_position) - i) << l_position | (lower & lower_bits_mask_position)) + bit_delta +
                   int64_t(bits_per_key_fixed_point * cum_keys >> 20);
    }

    uint64_t bitCountCumKeys() { return (num_buckets + 1) * l_cum_keys + num_buckets + 1 + (u_cum_keys >> l_cum_keys) + jump_size_words() / 2; }

    uint64_t bitCountPosition() { return (num_buckets + 1) * l_position + num_buckets + 1 + (u_position >> l_position) + jump_size_words() / 2; }
};

}  // namespace sux::function
