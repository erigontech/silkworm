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

#include <bit>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <span>
#include <vector>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/recsplit/encoding/sequence.hpp>
#include <silkworm/recsplit/support/common.hpp>

// EliasFano algo overview https://www.antoniomallia.it/sorted-integers-compression-with-elias-fano-encoding.html
// P. Elias. Efficient storage and retrieval by content and address of static files. J. ACM, 21(2):246–260, 1974.
// Partitioned Elias-Fano Indexes http://groups.di.unipi.it/~ottavian/files/elias_fano_sigir14.pdf

namespace silkworm::succinct {

//! Log2Q = Log2(Quantum)
static constexpr uint64_t kLog2q = 8;
//! Q = Quantum
static constexpr uint64_t kQ = 1 << kLog2q;  // 256
//! QMask = Quantum Mask
static constexpr uint64_t kQMask = kQ - 1;
//! SuperQ = Super Quantum
static constexpr uint64_t kSuperQ = 1 << 14;  // 16384
//! SuperQMask = SuperQuantum Mask
static constexpr uint64_t kSuperQMask = kSuperQ - 1;
static constexpr uint64_t kQPerSuperQ = kSuperQ / kQ;
static constexpr uint64_t kSuperQSize16 = 1 + kQPerSuperQ / 4;
static constexpr uint64_t kSuperQSize32 = 1 + kQPerSuperQ / 2;

template <class T, std::size_t Extent>
inline static void set(std::span<T, Extent> bits, const uint64_t pos) {
    bits[pos / 64] |= uint64_t(1) << (pos % 64);
}

//! This assumes that bits are set in monotonic order, so that we can skip the masking for the second word
template <class T, std::size_t Extent>
inline static void set_bits(std::span<T, Extent> bits, const uint64_t start, const uint64_t width, const uint64_t value) {
    const uint64_t shift = start & 63;
    const uint64_t mask = ((uint64_t(1) << width) - 1) << shift;
    const uint64_t idx64 = start >> 6;
    bits[idx64] = (bits[idx64] & ~mask) | (value << shift);
    if (shift + width > 64) {
        // Change two 64-bit words
        bits[idx64 + 1] = value >> (64 - shift);
    }
}

//! 32-bit Elias-Fano list that can be used to encode one monotone non-decreasing sequence
class EliasFanoList32 {
  public:
    EliasFanoList32(uint64_t count, uint64_t max_offset) {
        if (count == 0) throw std::logic_error{"too small count: " + std::to_string(count)};
        count_ = count - 1;
        max_offset_ = max_offset;
        u_ = max_offset + 1;
        words_upper_bits_ = derive_fields();
    }

    [[nodiscard]] std::size_t count() const { return count_ + 1; }

    [[nodiscard]] std::size_t max() const { return max_offset_; }

    [[nodiscard]] std::size_t min() const { return get(0); }

    [[nodiscard]] const Uint64Sequence& data() const { return data_; }

    [[nodiscard]] uint64_t get(uint64_t i) const {
        uint64_t lower = i * l_;
        uint64_t idx64 = lower / 64;
        uint64_t shift = lower % 64;
        lower = lower_bits_[idx64] >> shift;
        if (shift > 0) {
            lower |= lower_bits_[idx64 + 1] << (64 - shift);
        }

        const uint64_t jump_super_q = (i / kSuperQ) * kSuperQSize32;
        const uint64_t jump_inside_super_q = (i % kSuperQ) / kQ;
        idx64 = jump_super_q + 1 + (jump_inside_super_q >> 1);
        shift = 32 * (jump_inside_super_q % 2);
        const uint64_t mask = 0xffffffff << shift;
        const uint64_t jump = jump_[jump_super_q] + ((jump_[idx64] & mask) >> shift);

        uint64_t current_word = jump / 64;
        uint64_t window = upper_bits_[current_word] & (0xffffffffffffffff << (jump % 64));
        uint64_t d = i & kQMask;

        for (auto bit_count{std::popcount(window)}; uint64_t(bit_count) <= d; bit_count = std::popcount(window)) {
            current_word++;
            window = upper_bits_[current_word];
            d -= uint64_t(bit_count);
        }

        const uint64_t sel = select64(window, d);
        const auto value = ((current_word * 64 + sel - i) << l_ | (lower & lower_bits_mask_));
        return value;
    }

    void add_offset(uint64_t offset) {
        if (l_ != 0) {
            set_bits(lower_bits_, i_ * l_, l_, offset & lower_bits_mask_);
        }
        set(upper_bits_, (offset >> l_) + i_);
        i_++;
    }

    void build() {
        for (uint64_t i{0}, c{0}, last_super_q{0}; i < words_upper_bits_; ++i) {
            for (uint64_t b{0}; b < 64; ++b) {
                if ((upper_bits_[i] & (uint64_t(1) << b)) != 0) {
                    if ((c & kSuperQMask) == 0) {
                        /* When c is multiple of 2^14 (4096) */
                        jump_[(c / kSuperQ) * kSuperQSize32] = last_super_q = i * 64 + b;
                    }
                    if ((c & kQMask) == 0) {
                        /* When c is multiple of 2^8 (256) */
                        // offset can be either 0, 256, 512, ..., up to 4096-256
                        const uint64_t offset = i * 64 + b - last_super_q;
                        // offset needs to be encoded as 16-bit integer, therefore the following check
                        SILKWORM_ASSERT(offset < (uint64_t(1) << 32));
                        // c % superQ is the bit index inside the group of 4096 bits
                        const uint64_t jump_super_q = (c / kSuperQ) * kSuperQSize32;
                        const uint64_t jump_inside_super_q = (c % kSuperQ) / kQ;
                        const uint64_t idx64 = jump_super_q + 1 + (jump_inside_super_q >> 1);
                        const uint64_t shift = 32 * (jump_inside_super_q % 2);
                        const uint64_t mask = uint64_t(0xffffffff) << shift;
                        jump_[idx64] = (jump_[idx64] & ~mask) | (offset << shift);
                    }
                    c++;
                }
            }
        }
    }

    friend std::ostream& operator<<(std::ostream& os, const EliasFanoList32& ef) {
        Bytes uint64_buffer(8, '\0');

        endian::store_big_u64(uint64_buffer.data(), ef.count_);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written EF code count: " << ef.count_;

        endian::store_big_u64(uint64_buffer.data(), ef.u_);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
        SILK_DEBUG << "[index] written EF upper: " << ef.u_;

        os.write(reinterpret_cast<const char*>(ef.data_.data()), static_cast<std::streamsize>(ef.data_.size() * sizeof(uint64_t)));
        return os;
    }

  private:
    uint64_t derive_fields() {
        l_ = u_ / (count_ + 1) == 0 ? 0 : 63 ^ uint64_t(std::countl_zero(u_ / (count_ + 1)));
        lower_bits_mask_ = (uint64_t(1) << l_) - 1;

        uint64_t words_lower_bits = ((count_ + 1) * l_ + 63) / 64 + 1;
        uint64_t words_upper_bits = ((count_ + 1) + (u_ >> l_) + 63) / 64;
        uint64_t jump_words = jump_size_words();
        uint64_t total_words = words_lower_bits + words_upper_bits + jump_words;
        data_.resize(total_words);
        std::span data_span{data_.data(), data_.size()};
        lower_bits_ = data_span.subspan(0, words_lower_bits);
        upper_bits_ = data_span.subspan(words_lower_bits, words_upper_bits);
        jump_ = data_span.subspan(words_lower_bits + words_upper_bits, jump_words);

        return words_upper_bits;
    }

    [[nodiscard]] inline uint64_t jump_size_words() const {
        uint64_t size = ((count_ + 1) / kSuperQ) * kSuperQSize32;  // Whole blocks
        if ((count_ + 1) % kSuperQ != 0) {
            size += 1 + (((count_ + 1) % kSuperQ + kQ - 1) / kQ + 3) / 2;  // Partial block
        }
        return size;
    }

    Uint64Sequence data_;
    std::span<uint64_t> lower_bits_;
    std::span<uint64_t> upper_bits_;
    std::span<uint64_t> jump_;
    uint64_t lower_bits_mask_{0};
    uint64_t count_{0};
    uint64_t u_{0};
    uint64_t l_{0};
    uint64_t max_offset_{0};
    uint64_t i_{0};
    uint64_t words_upper_bits_{0};
};

//! 16-bit Double Elias-Fano list that used to encode *two* monotone non-decreasing sequences in RecSplit
//! @tparam AT a type of memory allocation out of util::AllocType
class DoubleEliasFanoList16 {
  public:
    DoubleEliasFanoList16() = default;

    [[nodiscard]] const Uint64Sequence& data() const { return data_; }

    [[nodiscard]] uint64_t num_buckets() const { return num_buckets_; }

    void build(const Uint64Sequence& cum_keys, const Uint64Sequence& position) {
        SILKWORM_ASSERT(cum_keys.size() == position.size());

        num_buckets_ = cum_keys.size() - 1;
        position_min_delta_ = std::numeric_limits<uint64_t>::max();
        cum_keys_min_delta_ = std::numeric_limits<uint64_t>::max();
        for (size_t i{1}; i <= num_buckets_; ++i) {
            SILKWORM_ASSERT(cum_keys[i] >= cum_keys[i - 1]);
            SILKWORM_ASSERT(position[i] >= position[i - 1]);
            const uint64_t nkeys_delta = cum_keys[i] - cum_keys[i - 1];
            cum_keys_min_delta_ = std::min(cum_keys_min_delta_, nkeys_delta);
            const uint64_t bucket_bits = position[i] - position[i - 1];
            position_min_delta_ = std::min(position_min_delta_, bucket_bits);
        }

        u_position = position[num_buckets_] - num_buckets_ * position_min_delta_ + 1;  // Largest possible encoding of the cumulated positions
        u_cum_keys = cum_keys[num_buckets_] - num_buckets_ * cum_keys_min_delta_ + 1;  // Largest possible encoding of the cumulated keys

        const auto [words_cum_keys, words_position] = derive_fields();
        for (uint64_t i{0}, cum_delta{0}, bit_delta{0}; i <= num_buckets_; i++, cum_delta += cum_keys_min_delta_, bit_delta += position_min_delta_) {
            if (l_cum_keys != 0) {
                set_bits(lower_bits, i * (l_cum_keys + l_position), l_cum_keys, (cum_keys[i] - cum_delta) & lower_bits_mask_cum_keys);
            }
            set(upper_bits_cum_keys, ((cum_keys[i] - cum_delta) >> l_cum_keys) + i);

            if (l_position != 0) {
                set_bits(lower_bits, i * (l_cum_keys + l_position) + l_cum_keys, l_position, (position[i] - bit_delta) & lower_bits_mask_position);
            }
            set(upper_bits_position, ((position[i] - bit_delta) >> l_position) + i);
        }

        // i iterates over the 64-bit words in the cumulative keys vector, c iterates over bits in the cumulative keys' words
        // last_super_q is the largest multiple of 2^14 (4096) which is no larger than c
        // (c / kSuperQ) is the index of the current 4096 block of bits
        // super_q_size is how many words is required to encode one block of 4096 bits. It is 17 words which is 1088 bits
        for (uint64_t i{0}, c{0}, last_super_q{0}; i < words_cum_keys; i++) {
            for (uint64_t b{0}; b < 64; b++) {
                if (upper_bits_cum_keys[i] & uint64_t(1) << b) {
                    if ((c & kSuperQMask) == 0) {
                        /* When c is multiple of 2^14 (4096) */
                        jump[(c / kSuperQ) * (kSuperQSize16 * 2)] = last_super_q = i * 64 + b;
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
                        const uint64_t mask = uint64_t(0xffff) << shift;
                        jump[idx64] = (jump[idx64] & ~mask) | (offset << shift);
                    }
                    c++;
                }
            }
        }

        for (uint64_t i{0}, c{0}, last_super_q{0}; i < words_position; i++) {
            for (uint64_t b = 0; b < 64; b++) {
                if (upper_bits_position[i] & uint64_t(1) << b) {
                    if ((c & kSuperQMask) == 0) {
                        jump[(c / kSuperQ) * (kSuperQSize16 * 2) + 1] = last_super_q = i * 64 + b;
                    }
                    if ((c & kQMask) == 0) {
                        const uint64_t offset = i * 64 + b - last_super_q;
                        SILKWORM_ASSERT(offset < (1 << 16));
                        const uint64_t jump_super_q = (c / kSuperQ) * (kSuperQSize16 * 2);
                        const uint64_t jump_inside_super_q = 2 * (c % kSuperQ) / kQ + 1;
                        const uint64_t idx64 = jump_super_q + 2 + (jump_inside_super_q >> 2);
                        const uint64_t shift = 16 * (jump_inside_super_q % 4);
                        const uint64_t mask = uint64_t(0xffff) << shift;
                        jump[idx64] = (jump[idx64] & ~mask) | (offset << shift);
                    }
                    c++;
                }
            }
        }
    }

    void get2(const uint64_t i, uint64_t& cum_keys, uint64_t& position) const {
        uint64_t window_cum_keys{0}, select_cum_keys{0}, curr_word_cum_keys{0}, lower{0}, cum_delta{0};
        get(i, cum_keys, position, window_cum_keys, select_cum_keys, curr_word_cum_keys, lower, cum_delta);
    }

    void get3(const uint64_t i, uint64_t& cum_keys, uint64_t& cum_keys_next, uint64_t& position) const {
        uint64_t window_cum_keys{0}, select_cum_keys{0}, curr_word_cum_keys{0}, lower{0}, cum_delta{0};
        get(i, cum_keys, position, window_cum_keys, select_cum_keys, curr_word_cum_keys, lower, cum_delta);
        window_cum_keys &= (uint64_t(0xffffffffffffffff) << select_cum_keys) << 1;
        while (window_cum_keys == 0) {
            curr_word_cum_keys++;
            window_cum_keys = upper_bits_cum_keys[curr_word_cum_keys];
        }
        lower >>= l_position;
        cum_keys_next = ((curr_word_cum_keys * 64 + static_cast<uint64_t>(rho(window_cum_keys)) - i - 1) << l_cum_keys | (lower & lower_bits_mask_cum_keys)) + cum_delta + cum_keys_min_delta_;
    }

  private:
    std::pair<uint64_t, uint64_t> derive_fields() {
        l_position = u_position / (num_buckets_ + 1) == 0 ? 0 : 63 ^ uint64_t(std::countl_zero(u_position / (num_buckets_ + 1)));
        l_cum_keys = u_cum_keys / (num_buckets_ + 1) == 0 ? 0 : 63 ^ uint64_t(std::countl_zero(u_cum_keys / (num_buckets_ + 1)));
        SILKWORM_ASSERT(l_cum_keys * 2 + l_position <= 56);

        lower_bits_mask_cum_keys = (1UL << l_cum_keys) - 1;
        lower_bits_mask_position = (1UL << l_position) - 1;

        const uint64_t words_lower_bits = lower_bits_size_words();
        const uint64_t words_cum_keys = cum_keys_size_words();
        const uint64_t words_position = position_size_words();
        const uint64_t jump_words = jump_size_words();
        const uint64_t total_words = words_lower_bits + words_cum_keys + words_position + jump_words;
        data_.resize(total_words);
        auto first = data_.data();
        lower_bits = std::span{first, first + words_lower_bits};
        first += words_lower_bits;
        upper_bits_cum_keys = std::span{first, first + words_cum_keys};
        first += words_cum_keys;
        upper_bits_position = std::span{first, first + words_position};
        first += words_position;
        jump = std::span{first, first + jump_words};

        return {words_cum_keys, words_position};
    }

    void get(const uint64_t i, uint64_t& cum_keys, uint64_t& position, uint64_t& window_cum_keys, uint64_t& select_cum_keys,
             uint64_t& curr_word_cum_keys, uint64_t& lower, uint64_t& cum_delta) const {
        const uint64_t pos_lower = i * (l_cum_keys + l_position);
        uint64_t idx64 = pos_lower / 64;
        uint64_t shift = pos_lower % 64;
        lower = lower_bits[idx64] >> shift;
        if (shift > 0) {
            lower |= lower_bits[idx64 + 1] << (64 - shift);
        }

        const uint64_t jump_super_q = (i / kSuperQ) * kSuperQSize16 * 2;
        const uint64_t jump_inside_super_q = (i % kSuperQ) / kQ;
        uint64_t idx16 = 4 * (jump_super_q + 2) + 2 * jump_inside_super_q;
        idx64 = idx16 / 4;
        shift = 16 * (idx16 % 4);
        uint64_t mask = uint64_t(0xffff) << shift;
        const uint64_t jump_cum_keys = jump[jump_super_q] + ((jump[idx64] & mask) >> shift);
        idx16++;
        idx64 = idx16 / 4;
        shift = 16 * (idx16 % 4);
        mask = uint64_t(0xffff) << shift;
        const uint64_t jump_position = jump[jump_super_q + 1] + ((jump[idx64] & mask) >> shift);

        curr_word_cum_keys = jump_cum_keys / 64;
        uint64_t curr_word_position = jump_position / 64;
        window_cum_keys = upper_bits_cum_keys[curr_word_cum_keys] & (uint64_t(0xffffffffffffffff) << (jump_cum_keys % 64));
        uint64_t window_position = upper_bits_position[curr_word_position] & (uint64_t(0xffffffffffffffff) << (jump_position % 64));
        uint64_t delta_cum_keys = i & kQMask;
        uint64_t delta_position = i & kQMask;

        for (auto bit_count{std::popcount(window_cum_keys)}; uint64_t(bit_count) <= delta_cum_keys; bit_count = std::popcount(window_cum_keys)) {
            curr_word_cum_keys++;
            window_cum_keys = upper_bits_cum_keys[curr_word_cum_keys];
            delta_cum_keys -= uint64_t(bit_count);
        }
        for (auto bit_count{std::popcount(window_position)}; uint64_t(bit_count) <= delta_position; bit_count = std::popcount(window_position)) {
            curr_word_position++;
            window_position = upper_bits_position[curr_word_position];
            delta_position -= uint64_t(bit_count);
        }

        select_cum_keys = select64(window_cum_keys, delta_cum_keys);
        cum_delta = i * cum_keys_min_delta_;
        cum_keys = ((curr_word_cum_keys * 64 + select_cum_keys - i) << l_cum_keys | (lower & lower_bits_mask_cum_keys)) + cum_delta;

        lower >>= l_cum_keys;

        const uint64_t select_position = select64(window_position, delta_position);
        const uint64_t bit_delta = i * position_min_delta_;
        position = ((curr_word_position * 64 + select_position - i) << l_position | (lower & lower_bits_mask_position)) + bit_delta;
    }

    Uint64Sequence data_;
    std::span<uint64_t> lower_bits;
    std::span<uint64_t> upper_bits_position;
    std::span<uint64_t> upper_bits_cum_keys;
    std::span<uint64_t> jump;
    uint64_t lower_bits_mask_cum_keys{0};
    uint64_t lower_bits_mask_position{0};

    //! Number of buckets
    uint64_t num_buckets_{0};

    uint64_t u_cum_keys{0}, u_position{0};
    uint64_t l_position{0}, l_cum_keys{0};

    //! Minimum delta between successive cumulative keys
    uint64_t cum_keys_min_delta_{0};

    //! Minimum delta between successive positions
    uint64_t position_min_delta_{0};

    [[nodiscard]] inline std::size_t lower_bits_size_words() const {
        return ((num_buckets_ + 1) * (l_cum_keys + l_position) + 63) / 64 + 1;
    }

    [[nodiscard]] inline std::size_t cum_keys_size_words() const {
        return (num_buckets_ + 1 + (u_cum_keys >> l_cum_keys) + 63) / 64;
    }

    [[nodiscard]] inline std::size_t position_size_words() const {
        return (num_buckets_ + 1 + (u_position >> l_position) + 63) / 64;
    }

    [[nodiscard]] inline std::size_t jump_size_words() const {
        // Compute whole blocks
        std::size_t size = ((num_buckets_ + 1) / kSuperQ) * kSuperQSize16 * 2;
        // Compute partial block (if any)
        if ((num_buckets_ + 1) % kSuperQ != 0) {
            size += (1 + (((num_buckets_ + 1) % kSuperQ + kQ - 1) / kQ + 3) / 4) * 2;
        }
        return size;
    }

    friend std::ostream& operator<<(std::ostream& os, const DoubleEliasFanoList16& ef) {
        Bytes uint64_buffer(8, '\0');

        endian::store_big_u64(uint64_buffer.data(), ef.num_buckets_);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

        endian::store_big_u64(uint64_buffer.data(), ef.u_cum_keys);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

        endian::store_big_u64(uint64_buffer.data(), ef.u_position);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

        endian::store_big_u64(uint64_buffer.data(), ef.cum_keys_min_delta_);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

        endian::store_big_u64(uint64_buffer.data(), ef.position_min_delta_);
        os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));

        // Erigon does not write data size here
        os.write(reinterpret_cast<const char*>(ef.data_.data()), static_cast<std::streamsize>(ef.data_.size() * sizeof(uint64_t)));
        return os;
    }

    friend std::istream& operator>>(std::istream& is, DoubleEliasFanoList16& ef) {
        Bytes uint64_buffer(8, '\0');

        is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
        ef.num_buckets_ = endian::load_big_u64(uint64_buffer.data());

        is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
        ef.u_cum_keys = endian::load_big_u64(uint64_buffer.data());

        is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
        ef.u_position = endian::load_big_u64(uint64_buffer.data());

        is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
        ef.cum_keys_min_delta_ = endian::load_big_u64(uint64_buffer.data());

        is.read(reinterpret_cast<char*>(uint64_buffer.data()), sizeof(uint64_t));
        ef.position_min_delta_ = endian::load_big_u64(uint64_buffer.data());

        ef.l_position = ef.u_position / (ef.num_buckets_ + 1) == 0 ? 0 : static_cast<uint64_t>(lambda(ef.u_position / (ef.num_buckets_ + 1)));
        ef.l_cum_keys = ef.u_cum_keys / (ef.num_buckets_ + 1) == 0 ? 0 : static_cast<uint64_t>(lambda(ef.u_cum_keys / (ef.num_buckets_ + 1)));
        SILKWORM_ASSERT(ef.l_cum_keys * 2 + ef.l_position <= 56);

        ef.lower_bits_mask_cum_keys = (1UL << ef.l_cum_keys) - 1;
        ef.lower_bits_mask_position = (1UL << ef.l_position) - 1;

        // Erigon assumes that data fills up the stream until the end
        int read_count{0};
        while (!is.eof()) {
            is.read(reinterpret_cast<char*>(ef.data_.data() + read_count), static_cast<std::streamsize>(sizeof(uint64_t)));
            ++read_count;
        }
        return is;
    }
};

}  // namespace silkworm::succinct
