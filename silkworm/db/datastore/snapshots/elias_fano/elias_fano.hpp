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
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "../common/encoding/sequence.hpp"
#include "../common/encoding/util.hpp"

// Elias-Fano encoding is a high bits / low bits representation of a monotonically increasing sequence of N > 0 natural numbers x[i]
// 0 <= x[0] <= x[1] <= ... <= x[N-2] <= x[N-1] <= U
// where U > 0 is an upper bound on the last value.

// EliasFano algorithm overview https://www.antoniomallia.it/sorted-integers-compression-with-elias-fano-encoding.html
// P. Elias. Efficient storage and retrieval by content and address of static files. J. ACM, 21(2):246–260, 1974.
// Partitioned Elias-Fano Indexes http://groups.di.unipi.it/~ottavian/files/elias_fano_sigir14.pdf

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

//! 32-bit Elias-Fano (EF) list that can be used to encode one monotone non-decreasing sequence
class EliasFanoList32 {
  public:
    static constexpr size_t kCountLength{sizeof(uint64_t)};
    static constexpr size_t kULength{sizeof(uint64_t)};

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    static EliasFanoList32 from_encoded_data(std::span<const uint8_t> encoded_data) {
        ensure(encoded_data.size() >= kCountLength + kULength, "EliasFanoList32::from_encoded_data data too short");
        const uint64_t count = endian::load_big_u64(encoded_data.data());
        const uint64_t u = endian::load_big_u64(encoded_data.subspan(kCountLength).data());
        const auto remaining_data = encoded_data.subspan(kCountLength + kULength);
        return EliasFanoList32{count, u, remaining_data};
    }

    //! Create an empty new 32-bit EF list prepared for the given data sequence length and max value
    //! \param sequence_length the length of the data sequence
    //! \param max_value the max value in the data sequence
    EliasFanoList32(uint64_t sequence_length, uint64_t max_value)
        : count_(sequence_length - 1),
          u_(max_value + 1),
          max_value_(max_value) {
        ensure(sequence_length > 0, "sequence length is zero");
        derive_fields();
    }

    //! Create a new 32-bit EF list from an existing data sequence
    //! \param count the number of EF data points
    //! \param u the strict upper bound on the EF data points, i.e. max value plus one
    //! \param data the existing data sequence (portion exceeding the total words will be ignored)
    EliasFanoList32(uint64_t count, uint64_t u, std::span<const uint8_t> data)
        : count_(count),
          u_(u),
          max_value_(u - 1) {
        const auto total_words = derive_fields();
        SILKWORM_ASSERT(total_words * sizeof(uint64_t) <= data.size());
        data = data.subspan(0, total_words * sizeof(uint64_t));
        std::copy(data.begin(), data.end(), reinterpret_cast<uint8_t*>(data_.data()));
    }

    size_t sequence_length() const {
        if (u_ == 0) return 0;
        return count_ + 1;
    }

    size_t count() const { return count_; }

    size_t max() const { return max_value_; }

    size_t min() const { return get(0); }

    const Uint64Sequence& data() const { return data_; }

    size_t encoded_data_size() const { return kCountLength + kULength + data_.size() * sizeof(uint64_t); }

    uint64_t get(uint64_t i) const {
        uint64_t lower = i * l_;
        size_t idx64 = lower / 64;
        uint64_t shift = lower % 64;
        SILKWORM_ASSERT(idx64 < lower_bits_.size());
        lower = lower_bits_[idx64] >> shift;
        if (shift > 0) {
            SILKWORM_ASSERT(idx64 + 1 < lower_bits_.size());
            lower |= lower_bits_[idx64 + 1] << (64 - shift);
        }

        const uint64_t jump_super_q = (i / kSuperQ) * kSuperQSize32;
        const uint64_t jump_inside_super_q = (i % kSuperQ) / kQ;
        idx64 = jump_super_q + 1 + (jump_inside_super_q >> 1);
        shift = 32 * (jump_inside_super_q % 2);
        const uint64_t mask = uint64_t{0xffffffff} << shift;
        SILKWORM_ASSERT(jump_super_q < jump_.size());
        SILKWORM_ASSERT(idx64 < jump_.size());
        const uint64_t jump = jump_[jump_super_q] + ((jump_[idx64] & mask) >> shift);

        uint64_t current_word = jump / 64;
        SILKWORM_ASSERT(current_word < upper_bits_.size());
        uint64_t window = upper_bits_[current_word] & (0xffffffffffffffff << (jump % 64));
        uint64_t d = i & kQMask;

        for (auto bit_count{std::popcount(window)}; static_cast<uint64_t>(bit_count) <= d; bit_count = std::popcount(window)) {
            ++current_word;
            SILKWORM_ASSERT(current_word < upper_bits_.size());
            window = upper_bits_[current_word];
            d -= static_cast<uint64_t>(bit_count);
        }

        const uint64_t sel = encoding::select64(window, d);
        const auto value = ((current_word * 64 + sel - i) << l_ | (lower & lower_bits_mask_));
        return value;
    }

    void add_offset(uint64_t offset) {
        if (l_ != 0) {
            set_bits(lower_bits_, i_ * l_, l_, offset & lower_bits_mask_);
        }
        set(upper_bits_, (offset >> l_) + i_);
        ++i_;
    }

    void build() {
        for (uint64_t i{0}, c{0}, last_super_q{0}; i < upper_bits_.size(); ++i) {
            for (uint64_t b{0}; b < 64; ++b) {
                if ((upper_bits_[i] & (uint64_t{1} << b)) != 0) {
                    if ((c & kSuperQMask) == 0) {
                        /* When c is multiple of 2^14 (4096) */
                        jump_[(c / kSuperQ) * kSuperQSize32] = last_super_q = i * 64 + b;
                    }
                    if ((c & kQMask) == 0) {
                        /* When c is multiple of 2^8 (256) */
                        // offset can be either 0, 256, 512, ..., up to 4096-256
                        const uint64_t offset = i * 64 + b - last_super_q;
                        // offset needs to be encoded as 16-bit integer, therefore the following check
                        SILKWORM_ASSERT(offset < (uint64_t{1} << 32));
                        // c % superQ is the bit index inside the group of 4096 bits
                        const uint64_t jump_super_q = (c / kSuperQ) * kSuperQSize32;
                        const uint64_t jump_inside_super_q = (c % kSuperQ) / kQ;
                        const uint64_t idx64 = jump_super_q + 1 + (jump_inside_super_q >> 1);
                        const uint64_t shift = 32 * (jump_inside_super_q % 2);
                        const uint64_t mask = uint64_t{0xffffffff} << shift;
                        jump_[idx64] = (jump_[idx64] & ~mask) | (offset << shift);
                    }
                    ++c;
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

    bool operator==(const EliasFanoList32& other) const {
        return (count_ == other.count_) &&
               (max_value_ == other.max_value_) &&
               (data_ == other.data_);
    }

    static EliasFanoList32 empty_list() {
        return EliasFanoList32{};
    }

  private:
    EliasFanoList32() {}

    uint64_t derive_fields() {
        l_ = u_ / (count_ + 1) == 0 ? 0 : 63 ^ static_cast<uint64_t>(std::countl_zero(u_ / (count_ + 1)));
        lower_bits_mask_ = (uint64_t{1} << l_) - 1;

        uint64_t words_lower_bits = ((count_ + 1) * l_ + 63) / 64 + 1;
        uint64_t words_upper_bits = ((count_ + 1) + (u_ >> l_) + 63) / 64;
        uint64_t jump_words = jump_size_words();
        uint64_t total_words = words_lower_bits + words_upper_bits + jump_words;
        data_.resize(total_words);
        lower_bits_ = std::span{data_.data(), words_lower_bits};
        upper_bits_ = std::span{data_.data() + words_lower_bits, words_upper_bits};
        jump_ = std::span{data_.data() + words_lower_bits + words_upper_bits, jump_words};

        return total_words;
    }

    uint64_t jump_size_words() const {
        uint64_t size = ((count_ + 1) / kSuperQ) * kSuperQSize32;  // Whole blocks
        if ((count_ + 1) % kSuperQ != 0) {
            size += 1 + (((count_ + 1) % kSuperQ + kQ - 1) / kQ + 3) / 2;  // Partial block
        }
        return size;
    }

    std::span<uint64_t> lower_bits_;
    std::span<uint64_t> upper_bits_;
    std::span<uint64_t> jump_;
    uint64_t lower_bits_mask_{0};
    uint64_t count_{0};
    uint64_t u_{0};
    uint64_t l_{0};
    uint64_t max_value_{0};
    uint64_t i_{0};
    Uint64Sequence data_;
};

//! 16-bit Double Elias-Fano list that used to encode *two* monotone non-decreasing sequences in RecSplit
class DoubleEliasFanoList16 {
  public:
    DoubleEliasFanoList16() = default;

    const Uint64Sequence& data() const { return data_; }

    uint64_t num_buckets() const { return num_buckets_; }

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

        // i iterates over the 64-bit words in the cumulative keys vector, c iterates over bits in the cumulative keys' words
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

    void get2(const uint64_t i, uint64_t& cum_keys, uint64_t& position) const {
        uint64_t window_cum_keys{0}, select_cum_keys{0}, curr_word_cum_keys{0}, lower{0}, cum_delta{0};
        get(i, cum_keys, position, window_cum_keys, select_cum_keys, curr_word_cum_keys, lower, cum_delta);
    }

    void get3(const uint64_t i, uint64_t& cum_keys, uint64_t& cum_keys_next, uint64_t& position) const {
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

  private:
    std::pair<uint64_t, uint64_t> derive_fields() {
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

    void get(const uint64_t i, uint64_t& cum_keys, uint64_t& position, uint64_t& window_cum_keys, uint64_t& select_cum_keys,
             uint64_t& curr_word_cum_keys, uint64_t& lower, uint64_t& cum_delta) const {
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

    Uint64Sequence data_;
    std::span<uint64_t> lower_bits_;
    std::span<uint64_t> upper_bits_position_;
    std::span<uint64_t> upper_bits_cum_keys_;
    std::span<uint64_t> jump_;
    uint64_t lower_bits_mask_cum_keys_{0};
    uint64_t lower_bits_mask_position_{0};

    //! Number of buckets
    uint64_t num_buckets_{0};

    uint64_t u_cum_keys_{0}, u_position_{0};
    uint64_t l_position_{0}, l_cum_keys_{0};

    //! Minimum delta between successive cumulative keys
    uint64_t cum_keys_min_delta_{0};

    //! Minimum delta between successive positions
    uint64_t position_min_delta_{0};

    size_t lower_bits_size_words() const {
        return ((num_buckets_ + 1) * (l_cum_keys_ + l_position_) + 63) / 64 + 1;
    }

    size_t cum_keys_size_words() const {
        return (num_buckets_ + 1 + (u_cum_keys_ >> l_cum_keys_) + 63) / 64;
    }

    size_t position_size_words() const {
        return (num_buckets_ + 1 + (u_position_ >> l_position_) + 63) / 64;
    }

    size_t jump_size_words() const {
        // Compute whole blocks
        size_t size = ((num_buckets_ + 1) / kSuperQ) * kSuperQSize16 * 2;
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

    friend std::istream& operator>>(std::istream& is, DoubleEliasFanoList16& ef) {
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
            is.read(reinterpret_cast<char*>(ef.data_.data() + read_count), static_cast<std::streamsize>(sizeof(uint64_t)));
            ++read_count;
        }
        if (!ef.data_.empty()) {
            ef.data_.pop_back();
        }
        ef.derive_fields();
        return is;
    }
};

}  // namespace silkworm::snapshots::elias_fano
