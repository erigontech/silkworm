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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/log.hpp>

#include "../common/encoding/sequence.hpp"
#include "../common/encoding/util.hpp"

namespace silkworm::snapshots::rec_split {

//! Storage for Golomb-Rice codes of a RecSplit bucket.
class GolombRiceVector {
  public:
    using Uint32Sequence = encoding::Uint32Sequence;
    using Uint64Sequence = encoding::Uint64Sequence;

    class Builder {
      public:
        static constexpr size_t kDefaultAllocatedWords{16};

        Builder() : Builder(kDefaultAllocatedWords) {}

        explicit Builder(const size_t allocated_words) : data_(allocated_words) {}

        void append_fixed(const uint64_t v, const uint64_t log2golomb) {
            if (log2golomb == 0) return;

            const uint64_t lower_bits = v & ((uint64_t{1} << log2golomb) - 1);
            size_t used_bits = bit_count_ & 63;

            data_.resize((bit_count_ + log2golomb + 63) / 64);

            uint64_t* append_ptr = data_.data() + bit_count_ / 64;
            uint64_t cur_word = *append_ptr;

            cur_word |= lower_bits << used_bits;
            if (used_bits + log2golomb > 64) {
                *(append_ptr++) = cur_word;
                cur_word = lower_bits >> (64 - used_bits);
            }
            *append_ptr = cur_word;
            bit_count_ += log2golomb;
        }

        void append_unary_all(const Uint32Sequence& unary) {
            size_t bit_inc = 0;
            for (const auto u : unary) {
                // Each number u uses u+1 bits for its unary representation
                bit_inc += u + 1;
            }

            data_.resize((bit_count_ + bit_inc + 63) / 64);

            for (const auto u : unary) {
                bit_count_ += u;
                uint64_t* append_ptr = data_.data() + bit_count_ / 64;
                *append_ptr |= uint64_t{1} << (bit_count_ & 63);
                ++bit_count_;
            }
        }

        uint64_t get_bits() const { return bit_count_; }

        GolombRiceVector build() {
            data_.resize(data_.size());
            return GolombRiceVector{std::move(data_)};
        }

        void append_unary(uint32_t unary) {
            unaries_.push_back(unary);
        }

        void append_collected_unaries() {
            append_unary_all(unaries_);
            unaries_.clear();
        }

      private:
        Uint64Sequence data_;
        size_t bit_count_{0};

        Uint32Sequence unaries_;
    };

    class LazyBuilder {
      public:
        static constexpr size_t kDefaultAllocatedWords{16};

        LazyBuilder() : LazyBuilder(kDefaultAllocatedWords) {}

        explicit LazyBuilder(const size_t allocated_words) {
            fixeds_.reserve(allocated_words);
            unaries_.reserve(allocated_words);
        }

        void append_fixed(const uint64_t v, const uint64_t log2golomb) {
            fixeds_.emplace_back(v, log2golomb);
        }

        void append_unary(uint32_t unary) {
            unaries_.push_back(unary);
        }

        void append_to(Builder& real_builder) {
            for (const auto& [v, log2golomb] : fixeds_) {
                real_builder.append_fixed(v, log2golomb);
            }
            real_builder.append_unary_all(unaries_);
        }

        void clear() {
            fixeds_.clear();
            unaries_.clear();
        }

      private:
        std::vector<std::pair<uint64_t, uint64_t>> fixeds_;
        Uint32Sequence unaries_;
    };

    GolombRiceVector() = default;
    explicit GolombRiceVector(std::vector<uint64_t> input_data) : data_(std::move(input_data)) {}

    size_t size() const { return data_.size(); }

    class Reader {
      public:
        explicit Reader(const Uint64Sequence& input_data) : data_(input_data) {}

        uint64_t read_next(const uint64_t log2golomb) {
            uint64_t result = 0;

            if (curr_window_unary_ == 0) {
                result += valid_lower_bits_unary_;
                curr_window_unary_ = *(curr_ptr_unary_++);
                valid_lower_bits_unary_ = 64;
                while (curr_window_unary_ == 0) {
                    [[unlikely]] result += 64;
                    curr_window_unary_ = *(curr_ptr_unary_++);
                }
            }

            const auto pos = static_cast<size_t>(encoding::rho(curr_window_unary_));

            curr_window_unary_ >>= pos;
            curr_window_unary_ >>= 1;
            valid_lower_bits_unary_ -= pos + 1;

            result += pos;
            result <<= log2golomb;

            size_t idx64 = curr_fixed_offset_ >> 6;
            uint64_t shift = curr_fixed_offset_ & 63;
            uint64_t fixed = data_[idx64] >> shift;
            if (shift + log2golomb > 64) {
                fixed |= data_[idx64 + 1] << (64 - shift);
            }
            result |= fixed & ((uint64_t{1} << log2golomb) - 1);
            curr_fixed_offset_ += log2golomb;
            return result;
        }

        void skip_subtree(const size_t nodes, const size_t fixed_len) {
            SILKWORM_ASSERT(nodes > 0);
            size_t missing = nodes, cnt = 0;
            while ((cnt = static_cast<size_t>(encoding::nu(curr_window_unary_))) < missing) {
                curr_window_unary_ = *(curr_ptr_unary_++);
                missing -= cnt;
                valid_lower_bits_unary_ = 64;
            }
            cnt = encoding::select64(curr_window_unary_, missing - 1);
            curr_window_unary_ >>= cnt;
            curr_window_unary_ >>= 1;
            valid_lower_bits_unary_ -= cnt + 1;

            curr_fixed_offset_ += fixed_len;
        }

        void read_reset(const size_t bit_pos, const size_t unary_offset) {
            curr_fixed_offset_ = bit_pos;
            size_t unary_pos = bit_pos + unary_offset;
            curr_ptr_unary_ = data_.data() + unary_pos / 64;
            curr_window_unary_ = *(curr_ptr_unary_++) >> (unary_pos & 63);
            valid_lower_bits_unary_ = 64 - (unary_pos & 63);
        }

      private:
        const Uint64Sequence& data_;
        size_t curr_fixed_offset_{0};
        uint64_t curr_window_unary_{0};
        uint64_t const* curr_ptr_unary_{nullptr};
        size_t valid_lower_bits_unary_{0};
    };

    Reader reader() const { return Reader{data_}; }

  private:
    encoding::Uint64Sequence data_;

    friend std::ostream& operator<<(std::ostream& os, const GolombRiceVector& rbv) {
        using namespace encoding;
        os << rbv.data_;
        return os;
    }

    friend std::istream& operator>>(std::istream& is, GolombRiceVector& rbv) {
        using namespace encoding;
        is >> rbv.data_;
        return is;
    }
};

}  // namespace silkworm::snapshots::rec_split
