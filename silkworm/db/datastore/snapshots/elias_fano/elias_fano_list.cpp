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

#include "elias_fano_list.hpp"

#include <algorithm>
#include <bit>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "../common/encoding/util.hpp"
#include "../common/util/iterator/index_range.hpp"
#include "elias_fano_common.hpp"

namespace silkworm::snapshots::elias_fano {

EliasFanoList32 EliasFanoList32::from_encoded_data(std::span<const uint8_t> encoded_data) {
    ensure(encoded_data.size() >= kCountLength + kULength, "EliasFanoList32::from_encoded_data data too short");
    const uint64_t last = endian::load_big_u64(encoded_data.data());
    const uint64_t u = endian::load_big_u64(encoded_data.subspan(kCountLength).data());
    const auto remaining_data = encoded_data.subspan(kCountLength + kULength);
    return EliasFanoList32{last + 1, u - 1, remaining_data};
}

EliasFanoList32 EliasFanoList32::from_encoded_data(ByteView encoded_data) {
    return from_encoded_data(std::span<const uint8_t>{encoded_data});
}

EliasFanoList32 EliasFanoList32::from_encoded_data(Bytes encoded_data) {
    auto elias_fano_list = from_encoded_data(std::span<const uint8_t>{encoded_data});
    elias_fano_list.data_holder_ = std::move(encoded_data);
    return elias_fano_list;
}

EliasFanoList32::EliasFanoList32(uint64_t count, uint64_t max_value, std::span<const uint8_t> encoded_data)
    : count_{count},
      u_{max_value + 1},
      data_{reinterpret_cast<const uint64_t*>(encoded_data.data()), EliasFanoList32::total_words(count, max_value)} {
    SILKWORM_ASSERT(EliasFanoList32::total_words(count, max_value) * sizeof(uint64_t) <= encoded_data.size());
    derive_fields();
}

uint64_t EliasFanoList32::at(size_t i) const {
    uint64_t lower = i * l_;
    size_t idx64 = lower / 64;
    uint64_t shift = lower % 64;
    SILKWORM_ASSERT(idx64 < lower_bits_.size());
    lower = lower_bits_[idx64] >> shift;
    if (shift > 0) {
        SILKWORM_ASSERT(idx64 + 1 < lower_bits_.size());
        lower |= lower_bits_[idx64 + 1] << (64 - shift);
    }

    const uint64_t value = ((upper(i) << l_) | (lower & lower_bits_mask_));
    return value;
}

uint64_t EliasFanoList32::upper(uint64_t i) const {
    const uint64_t jump_super_q = (i / kSuperQ) * kSuperQSize32;
    const uint64_t jump_inside_super_q = (i % kSuperQ) / kQ;
    const uint64_t idx64 = jump_super_q + 1 + (jump_inside_super_q >> 1);
    const uint64_t shift = 32 * (jump_inside_super_q % 2);
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
    const uint64_t value = current_word * 64 + sel - i;
    return value;
}

std::optional<std::pair<size_t, uint64_t>> EliasFanoList32::seek([[maybe_unused]] uint64_t v, bool reverse) const {
    if (count_ == 0) {
        return std::nullopt;
    }

    uint64_t min = this->min();
    uint64_t max = this->max();

    if (v == 0) {
        if (!reverse || (min == 0)) return std::pair{0, min};
        return std::nullopt;
    }

    size_t last = count_ - 1;

    if (v == max) {
        return std::pair{last, max};
    }
    if (v > max) {
        if (reverse) return std::pair{last, max};
        return std::nullopt;
    }

    uint64_t hi = v >> l_;
    IndexRange index_range{0, count_};
    IndexRange::Iterator start_it = std::ranges::partition_point(index_range, [reverse, last, hi, this](size_t i) -> bool {
        return reverse ? (upper(last - i) > hi) : (upper(i) < hi);
    });

    for (size_t j = *start_it; j < count_; j++) {
        size_t idx = reverse ? last - j : j;
        uint64_t val = at(idx);
        if (reverse ? (val <= v) : (val >= v)) {
            return std::pair{idx, val};
        }
    }

    return std::nullopt;
}

std::ostream& operator<<(std::ostream& os, const EliasFanoList32& ef) {
    Bytes uint64_buffer(8, '\0');

    endian::store_big_u64(uint64_buffer.data(), ef.count_ - 1);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
    SILK_DEBUG << "[index] written EF code count: " << ef.count_ - 1;

    endian::store_big_u64(uint64_buffer.data(), ef.u_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
    SILK_DEBUG << "[index] written EF upper: " << ef.u_;

    os.write(reinterpret_cast<const char*>(ef.data_.data()), static_cast<std::streamsize>(ef.data_.size() * sizeof(uint64_t)));
    return os;
}

uint64_t EliasFanoList32::total_words(uint64_t count, uint64_t max_value) {
    ensure(count > 0, "EliasFanoList32 size is zero");
    const uint64_t u = max_value + 1;
    const uint64_t l = (u / count == 0) ? 0 : (63 ^ static_cast<uint64_t>(std::countl_zero(u / count)));

    const uint64_t words_lower_bits = (count * l + 63) / 64 + 1;
    const uint64_t words_upper_bits = (count + (u >> l) + 63) / 64;
    const uint64_t jump_words = jump_size_words(count);
    const uint64_t total_words = words_lower_bits + words_upper_bits + jump_words;
    return total_words;
}

uint64_t EliasFanoList32::jump_size_words(uint64_t count) {
    uint64_t size = (count / kSuperQ) * kSuperQSize32;  // Whole blocks
    if (count % kSuperQ != 0) {
        size += 1 + ((count % kSuperQ + kQ - 1) / kQ + 3) / 2;  // Partial block
    }
    return size;
}

uint64_t EliasFanoList32::derive_fields() {
    ensure(count_ > 0, "EliasFanoList32 size is zero");
    l_ = (u_ / count_ == 0) ? 0 : (63 ^ static_cast<uint64_t>(std::countl_zero(u_ / count_)));
    lower_bits_mask_ = (uint64_t{1} << l_) - 1;

    uint64_t words_lower_bits = (count_ * l_ + 63) / 64 + 1;
    uint64_t words_upper_bits = (count_ + (u_ >> l_) + 63) / 64;
    uint64_t jump_words = jump_size_words(count_);
    uint64_t total_words = words_lower_bits + words_upper_bits + jump_words;
    lower_bits_ = data_.subspan(0, words_lower_bits);
    upper_bits_ = data_.subspan(words_lower_bits, words_upper_bits);
    jump_ = data_.subspan(words_lower_bits + words_upper_bits, jump_words);

    return total_words;
}

EliasFanoList32Builder::EliasFanoList32Builder(uint64_t count, uint64_t max_value)
    : count_{count},
      u_{max_value + 1} {
    derive_fields();
}

void EliasFanoList32Builder::add_offset(uint64_t offset) {
    if (l_ != 0) {
        set_bits(lower_bits_, i_ * l_, l_, offset & lower_bits_mask_);
    }
    set(upper_bits_, (offset >> l_) + i_);
    ++i_;
}

void EliasFanoList32Builder::build() {
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

uint64_t EliasFanoList32Builder::derive_fields() {
    ensure(count_ > 0, "EliasFanoList32Builder size is zero");
    l_ = (u_ / count_ == 0) ? 0 : (63 ^ static_cast<uint64_t>(std::countl_zero(u_ / count_)));
    lower_bits_mask_ = (uint64_t{1} << l_) - 1;

    uint64_t words_lower_bits = (count_ * l_ + 63) / 64 + 1;
    uint64_t words_upper_bits = (count_ + (u_ >> l_) + 63) / 64;
    uint64_t jump_words = EliasFanoList32::jump_size_words(count_);
    uint64_t total_words = words_lower_bits + words_upper_bits + jump_words;
    data_.resize(total_words);
    lower_bits_ = std::span{data_.data(), words_lower_bits};
    upper_bits_ = std::span{data_.data() + words_lower_bits, words_upper_bits};
    jump_ = std::span{data_.data() + words_lower_bits + words_upper_bits, jump_words};

    return total_words;
}

std::ostream& operator<<(std::ostream& os, const EliasFanoList32Builder& ef) {
    Bytes uint64_buffer(8, '\0');

    endian::store_big_u64(uint64_buffer.data(), ef.count_ - 1);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
    SILK_DEBUG << "[index] written EF code count: " << ef.count_ - 1;

    endian::store_big_u64(uint64_buffer.data(), ef.u_);
    os.write(reinterpret_cast<const char*>(uint64_buffer.data()), sizeof(uint64_t));
    SILK_DEBUG << "[index] written EF upper: " << ef.u_;

    os.write(reinterpret_cast<const char*>(ef.data_.data()), static_cast<std::streamsize>(ef.data_.size() * sizeof(uint64_t)));
    return os;
}

}  // namespace silkworm::snapshots::elias_fano
