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

#include "double_elias_fano_list.hpp"

#include <bit>
#include <limits>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>

#include "../common/encoding/util.hpp"
#include "elias_fano_common.hpp"

namespace silkworm::snapshots::elias_fano {

void DoubleEliasFanoList16::build(const Uint64Sequence& cum_keys, const Uint64Sequence& position) {
    SILKWORM_ASSERT(cum_keys.size() == position.size());

    num_buckets_ = cum_keys.size() - 1;
    position_min_delta_ = std::numeric_limits<uint64_t>::max();
    cum_keys_min_delta_ = std::numeric_limits<uint64_t>::max();
    for (size_t i{1}; i <= num_buckets_; ++i) {
        SILKWORM_ASSERT(cum_keys[i] >= cum_keys[i - 1]);
        SILKWORM_ASSERT(position[i] >= position[i - 1]);
        const uint64_t n_keys_delta = cum_keys[i] - cum_keys[i - 1];
        cum_keys_min_delta_ = std::min(cum_keys_min_delta_, n_keys_delta);
        const uint64_t bucket_bits = position[i] - position[i - 1];
        position_min_delta_ = std::min(position_min_delta_, bucket_bits);
    }

    u_position_ = position[num_buckets_] - num_buckets_ * position_min_delta_ + 1;  // Largest possible encoding of the cumulated positions
    u_cum_keys_ = cum_keys[num_buckets_] - num_buckets_ * cum_keys_min_delta_ + 1;  // Largest possible encoding of the cumulated keys

    const auto [words_cum_keys, words_position] = derive_fields();
    for (uint64_t i{0}, cum_delta{0}, bit_delta{0}; i <= num_buckets_; ++i, cum_delta += cum_keys_min_delta_, bit_delta += position_min_delta_) {
        if (l_cum_keys_ != 0) {
            set_bits(lower_bits_, i * (l_cum_keys_ + l_position_), l_cum_keys_, (cum_keys[i] - cum_delta) & lower_bits_mask_cum_keys_);
        }
        set(upper_bits_cum_keys_, ((cum_keys[i] - cum_delta) >> l_cum_keys_) + i);

        if (l_position_ != 0) {
            set_bits(lower_bits_, i * (l_cum_keys_ + l_position_) + l_cum_keys_, l_position_, (position[i] - bit_delta) & lower_bits_mask_position_);
        }
        set(upper_bits_position_, ((position[i] - bit_delta) >> l_position_) + i);
    }

    // iterate over the 64-bit words in the cumulative keys vector, c iterates over bits in the cumulative keys' words
    // last_super_q is the largest multiple of 2^14 (4096) which is no larger than c
    // (c / kSuperQ) is the index of the current 4096 block of bits
    // super_q_size is how many words is required to encode one block of 4096 bits. It is 17 words which is 1088 bits
    for (uint64_t i{0}, c{0}, last_super_q{0}; i < words_cum_keys; ++i) {
        for (uint64_t b{0}; b < 64; ++b) {
            if (upper_bits_cum_keys_[i] & uint64_t{1} << b) {
                if ((c & kSuperQMask) == 0) {
                    /* When c is multiple of 2^14 (4096) */
                    jump_[(c / kSuperQ) * (kSuperQSize16 * 2)] = last_super_q = i * 64 + b;
                }
                if ((c & kQMask) == 0) {
                    /* When c is multiple of 2^8 (256) */
                    // offset can be either 0, 256, 512, ..., up to 4096-256
                    const uint64_t offset = i * 64 + b - last_super_q;
                    // offset needs to be encoded as 16-bit integer, therefore the following check
                    SILKWORM_ASSERT(offset < (1 << 16));
                    // c % superQ is the bit index inside the group of 4096 bits
                    const uint64_t jump_super_q = (c / kSuperQ) * (kSuperQSize16 * 2);
                    const uint64_t jump_inside_super_q = 2 * (c % kSuperQ) / kQ;
                    const uint64_t idx64 = jump_super_q + 2 + (jump_inside_super_q >> 2);
                    const uint64_t shift = 16 * (jump_inside_super_q % 4);
                    const uint64_t mask = uint64_t{0xffff} << shift;
                    jump_[idx64] = (jump_[idx64] & ~mask) | (offset << shift);
                }
                ++c;
            }
        }
    }

    for (uint64_t i{0}, c{0}, last_super_q{0}; i < words_position; ++i) {
        for (uint64_t b = 0; b < 64; ++b) {
            if (upper_bits_position_[i] & uint64_t{1} << b) {
                if ((c & kSuperQMask) == 0) {
                    jump_[(c / kSuperQ) * (kSuperQSize16 * 2) + 1] = last_super_q = i * 64 + b;
                }
                if ((c & kQMask) == 0) {
                    const uint64_t offset = i * 64 + b - last_super_q;
                    SILKWORM_ASSERT(offset < (1 << 16));
                    const uint64_t jump_super_q = (c / kSuperQ) * (kSuperQSize16 * 2);
                    const uint64_t jump_inside_super_q = 2 * (c % kSuperQ) / kQ + 1;
                    const uint64_t idx64 = jump_super_q + 2 + (jump_inside_super_q >> 2);
                    const uint64_t shift = 16 * (jump_inside_super_q % 4);
                    const uint64_t mask = uint64_t{0xffff} << shift;
                    jump_[idx64] = (jump_[idx64] & ~mask) | (offset << shift);
                }
                ++c;
            }
        }
    }
}

void DoubleEliasFanoList16::get2(const uint64_t i, uint64_t& cum_keys, uint64_t& position) const {
    uint64_t window_cum_keys{0}, select_cum_keys{0}, curr_word_cum_keys{0}, lower{0}, cum_delta{0};
    get(i, cum_keys, position, window_cum_keys, select_cum_keys, curr_word_cum_keys, lower, cum_delta);
}

void DoubleEliasFanoList16::get3(const uint64_t i, uint64_t& cum_keys, uint64_t& cum_keys_next, uint64_t& position) const {
    uint64_t window_cum_keys{0}, select_cum_keys{0}, curr_word_cum_keys{0}, lower{0}, cum_delta{0};
    get(i, cum_keys, position, window_cum_keys, select_cum_keys, curr_word_cum_keys, lower, cum_delta);
    window_cum_keys &= (uint64_t{0xffffffffffffffff} << select_cum_keys) << 1;
    while (window_cum_keys == 0) {
        ++curr_word_cum_keys;
        window_cum_keys = upper_bits_cum_keys_[curr_word_cum_keys];
    }
    lower >>= l_position_;
    cum_keys_next = ((curr_word_cum_keys * 64 + static_cast<uint64_t>(encoding::rho(window_cum_keys)) - i - 1) << l_cum_keys_ | (lower & lower_bits_mask_cum_keys_)) + cum_delta + cum_keys_min_delta_;
}

std::pair<uint64_t, uint64_t> DoubleEliasFanoList16::derive_fields() {
    l_position_ = u_position_ / (num_buckets_ + 1) == 0 ? 0 : 63 ^ static_cast<uint64_t>(std::countl_zero(u_position_ / (num_buckets_ + 1)));
    l_cum_keys_ = u_cum_keys_ / (num_buckets_ + 1) == 0 ? 0 : 63 ^ static_cast<uint64_t>(std::countl_zero(u_cum_keys_ / (num_buckets_ + 1)));
    SILKWORM_ASSERT(l_cum_keys_ * 2 + l_position_ <= 56);

    lower_bits_mask_cum_keys_ = (1UL << l_cum_keys_) - 1;
    lower_bits_mask_position_ = (1UL << l_position_) - 1;

    const uint64_t words_lower_bits = lower_bits_size_words();
    const uint64_t words_cum_keys = cum_keys_size_words();
    const uint64_t words_position = position_size_words();
    const uint64_t jump_words = jump_size_words();
    const uint64_t total_words = words_lower_bits + words_cum_keys + words_position + jump_words;
    data_.resize(total_words);
    auto first = data_.data();
    lower_bits_ = std::span{first, first + words_lower_bits};
    first += words_lower_bits;
    upper_bits_cum_keys_ = std::span{first, first + words_cum_keys};
    first += words_cum_keys;
    upper_bits_position_ = std::span{first, first + words_position};
    first += words_position;
    jump_ = std::span{first, first + jump_words};

    return {words_cum_keys, words_position};
}

void DoubleEliasFanoList16::get(
    const uint64_t i,
    uint64_t& cum_keys,
    uint64_t& position,
    uint64_t& window_cum_keys,
    uint64_t& select_cum_keys,
    uint64_t& curr_word_cum_keys,
    uint64_t& lower,
    uint64_t& cum_delta) const {
    const uint64_t pos_lower = i * (l_cum_keys_ + l_position_);
    uint64_t idx64 = pos_lower / 64;
    uint64_t shift = pos_lower % 64;
    lower = lower_bits_[idx64] >> shift;
    if (shift > 0) {
        lower |= lower_bits_[idx64 + 1] << (64 - shift);
    }

    const uint64_t jump_super_q = (i / kSuperQ) * kSuperQSize16 * 2;
    const uint64_t jump_inside_super_q = (i % kSuperQ) / kQ;
    uint64_t idx16 = 4 * (jump_super_q + 2) + 2 * jump_inside_super_q;
    idx64 = idx16 / 4;
    shift = 16 * (idx16 % 4);
    uint64_t mask = uint64_t{0xffff} << shift;
    const uint64_t jump_cum_keys = jump_[jump_super_q] + ((jump_[idx64] & mask) >> shift);
    ++idx16;
    idx64 = idx16 / 4;
    shift = 16 * (idx16 % 4);
    mask = uint64_t{0xffff} << shift;
    const uint64_t jump_position = jump_[jump_super_q + 1] + ((jump_[idx64] & mask) >> shift);

    curr_word_cum_keys = jump_cum_keys / 64;
    uint64_t curr_word_position = jump_position / 64;
    window_cum_keys = upper_bits_cum_keys_[curr_word_cum_keys] & (uint64_t{0xffffffffffffffff} << (jump_cum_keys % 64));
    uint64_t window_position = upper_bits_position_[curr_word_position] & (uint64_t{0xffffffffffffffff} << (jump_position % 64));
    uint64_t delta_cum_keys = i & kQMask;
    uint64_t delta_position = i & kQMask;

    for (auto bit_count{std::popcount(window_cum_keys)}; static_cast<uint64_t>(bit_count) <= delta_cum_keys; bit_count = std::popcount(window_cum_keys)) {
        ++curr_word_cum_keys;
        window_cum_keys = upper_bits_cum_keys_[curr_word_cum_keys];
        delta_cum_keys -= static_cast<uint64_t>(bit_count);
    }
    for (auto bit_count{std::popcount(window_position)}; static_cast<uint64_t>(bit_count) <= delta_position; bit_count = std::popcount(window_position)) {
        ++curr_word_position;
        window_position = upper_bits_position_[curr_word_position];
        delta_position -= static_cast<uint64_t>(bit_count);
    }

    select_cum_keys = encoding::select64(window_cum_keys, delta_cum_keys);
    cum_delta = i * cum_keys_min_delta_;
    cum_keys = ((curr_word_cum_keys * 64 + select_cum_keys - i) << l_cum_keys_ | (lower & lower_bits_mask_cum_keys_)) + cum_delta;

    lower >>= l_cum_keys_;

    const uint64_t select_position = encoding::select64(window_position, delta_position);
    const uint64_t bit_delta = i * position_min_delta_;
    position = ((curr_word_position * 64 + select_position - i) << l_position_ | (lower & lower_bits_mask_position_)) + bit_delta;
}

size_t DoubleEliasFanoList16::jump_size_words() const {
    // Compute whole blocks
    size_t size = ((num_buckets_ + 1) / kSuperQ) * kSuperQSize16 * 2;
    // Compute partial block (if any)
    if ((num_buckets_ + 1) % kSuperQ != 0) {
        size += (1 + (((num_buckets_ + 1) % kSuperQ + kQ - 1) / kQ + 3) / 4) * 2;
    }
    return size;
}

std::ostream& operator<<(std::ostream& os, const DoubleEliasFanoList16& ef) {
    Bytes uint64_buffer(8, '\0');

    endian::store_big_u64(uint64_buffer.data(), ef.num_buckets_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

    endian::store_big_u64(uint64_buffer.data(), ef.u_cum_keys_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

    endian::store_big_u64(uint64_buffer.data(), ef.u_position_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

    endian::store_big_u64(uint64_buffer.data(), ef.cum_keys_min_delta_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

    endian::store_big_u64(uint64_buffer.data(), ef.position_min_delta_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

    // Erigon does not write data size here
    os.write(reinterpret_cast<const char*>(ef.data_.data()), static_cast<std::streamsize>(ef.data_.size() * sizeof(uint64_t)));
    return os;
}

std::istream& operator>>(std::istream& is, DoubleEliasFanoList16& ef) {
    Bytes uint64_buffer(8, '\0');

    is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
    ef.num_buckets_ = endian::load_big_u64(uint64_buffer.data());

    is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
    ef.u_cum_keys_ = endian::load_big_u64(uint64_buffer.data());

    is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
    ef.u_position_ = endian::load_big_u64(uint64_buffer.data());

    is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
    ef.cum_keys_min_delta_ = endian::load_big_u64(uint64_buffer.data());

    is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
    ef.position_min_delta_ = endian::load_big_u64(uint64_buffer.data());

    ef.l_position_ = ef.u_position_ / (ef.num_buckets_ + 1) == 0 ? 0 : static_cast<uint64_t>(encoding::lambda(ef.u_position_ / (ef.num_buckets_ + 1)));
    ef.l_cum_keys_ = ef.u_cum_keys_ / (ef.num_buckets_ + 1) == 0 ? 0 : static_cast<uint64_t>(encoding::lambda(ef.u_cum_keys_ / (ef.num_buckets_ + 1)));
    SILKWORM_ASSERT(ef.l_cum_keys_ * 2 + ef.l_position_ <= 56);

    ef.lower_bits_mask_cum_keys_ = (1UL << ef.l_cum_keys_) - 1;
    ef.lower_bits_mask_position_ = (1UL << ef.l_position_) - 1;

    // Erigon assumes that data fills up the stream until the end
    size_t read_count{0};
    while (!is.eof()) {
        ef.data_.resize(read_count + 1);
        is.read(reinterpret_cast<char*>(ef.data_.data() + read_count), sizeof(uint64_t));
        ++read_count;
    }
    if (!ef.data_.empty()) {
        ef.data_.pop_back();
    }
    ef.derive_fields();
    return is;
}

}  // namespace silkworm::snapshots::elias_fano
