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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iostream>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/recsplit/encoding/sequence.hpp>
#include <silkworm/node/recsplit/support/common.hpp>

namespace silkworm::succinct {

//! Storage for Golomb-Rice codes of a RecSplit bucket.
class GolombRiceVector {
  public:
    class Builder {
      public:
        static constexpr std::size_t kDefaultAllocatedWords{16};

        Builder() : Builder(kDefaultAllocatedWords) {}

        explicit Builder(const std::size_t allocated_words) : data(allocated_words) {}

        void append_fixed(const uint64_t v, const uint64_t log2golomb) {
            if (log2golomb == 0) return;

            const uint64_t lower_bits = v & ((uint64_t(1) << log2golomb) - 1);
            std::size_t used_bits = bit_count & 63;

            data.resize((bit_count + log2golomb + 63) / 64);

            uint64_t* append_ptr = data.data() + bit_count / 64;
            uint64_t cur_word = *append_ptr;

            cur_word |= lower_bits << used_bits;
            if (used_bits + log2golomb > 64) {
                *(append_ptr++) = cur_word;
                cur_word = lower_bits >> (64 - used_bits);
            }
            *append_ptr = cur_word;
            bit_count += log2golomb;
        }

        void append_unary_all(const Uint32Sequence& unary) {
            std::size_t bit_inc = 0;
            for (const auto u : unary) {
                // Each number u uses u+1 bits for its unary representation
                bit_inc += u + 1;
            }

            data.resize((bit_count + bit_inc + 63) / 64);

            for (const auto u : unary) {
                bit_count += u;
                uint64_t* append_ptr = data.data() + bit_count / 64;
                *append_ptr |= uint64_t(1) << (bit_count & 63);
                ++bit_count;
            }
        }

        [[nodiscard]] uint64_t get_bits() const { return bit_count; }

        GolombRiceVector build() {
            data.resize(data.size());
            return GolombRiceVector{std::move(data)};
        }

      private:
        Uint64Sequence data;
        std::size_t bit_count{0};
    };

    class LazyBuilder {  // todo(mike): find a better solution
      public:
        static constexpr std::size_t kDefaultAllocatedWords{16};

        LazyBuilder() : LazyBuilder(kDefaultAllocatedWords) {}

        explicit LazyBuilder(const std::size_t allocated_words) {
            fixeds.reserve(allocated_words);
            unaries.reserve(allocated_words);
        }

        void append_fixed(const uint64_t v, const uint64_t log2golomb) {
            fixeds.emplace_back(v, log2golomb);
        }

        void append_unary(uint32_t unary) {
            unaries.push_back(unary);
        }

        void append_to(Builder& real_builder) {
            for (const auto& [v, log2golomb] : fixeds) {
                real_builder.append_fixed(v, log2golomb);
            }
            real_builder.append_unary_all(unaries);
        }

        void clear() {
            fixeds.clear();
            unaries.clear();
        }

      private:
        std::vector<std::pair<uint64_t, uint64_t>> fixeds;
        Uint32Sequence unaries;
    };

    GolombRiceVector() = default;
    explicit GolombRiceVector(std::vector<uint64_t>&& input_data) : data(std::move(input_data)) {}

    [[nodiscard]] std::size_t size() const { return data.size(); }

    class Reader {
      public:
        explicit Reader(const Uint64Sequence& input_data) : data(input_data) {}

        uint64_t read_next(const uint64_t log2golomb) {
            uint64_t result = 0;

            if (curr_window_unary == 0) {
                result += valid_lower_bits_unary;
                curr_window_unary = *(curr_ptr_unary++);
                valid_lower_bits_unary = 64;
                while (curr_window_unary == 0) {
                    [[unlikely]] result += 64;
                    curr_window_unary = *(curr_ptr_unary++);
                }
            }

            const auto pos = static_cast<std::size_t>(rho(curr_window_unary));

            curr_window_unary >>= pos;
            curr_window_unary >>= 1;
            valid_lower_bits_unary -= pos + 1;

            result += pos;
            result <<= log2golomb;

            std::size_t idx64 = curr_fixed_offset >> 6;
            uint64_t shift = curr_fixed_offset & 63;
            uint64_t fixed = data[idx64] >> shift;
            if (shift + log2golomb > 64) {
                fixed |= data[idx64 + 1] << (64 - shift);
            }
            result |= fixed & ((uint64_t(1) << log2golomb) - 1);
            curr_fixed_offset += log2golomb;
            return result;
        }

        void skip_subtree(const std::size_t nodes, const std::size_t fixed_len) {
            SILKWORM_ASSERT(nodes > 0);
            std::size_t missing = nodes, cnt;
            while ((cnt = static_cast<std::size_t>(nu(curr_window_unary))) < missing) {
                curr_window_unary = *(curr_ptr_unary++);
                missing -= cnt;
                valid_lower_bits_unary = 64;
            }
            cnt = select64(curr_window_unary, missing - 1);
            curr_window_unary >>= cnt;
            curr_window_unary >>= 1;
            valid_lower_bits_unary -= cnt + 1;

            curr_fixed_offset += fixed_len;
        }

        void read_reset(const std::size_t bit_pos, const std::size_t unary_offset) {
            curr_fixed_offset = bit_pos;
            std::size_t unary_pos = bit_pos + unary_offset;
            curr_ptr_unary = data.data() + unary_pos / 64;
            curr_window_unary = *(curr_ptr_unary++) >> (unary_pos & 63);
            valid_lower_bits_unary = 64 - (unary_pos & 63);
        }

      private:
        const Uint64Sequence& data;
        std::size_t curr_fixed_offset{0};
        uint64_t curr_window_unary{0};
        uint64_t const* curr_ptr_unary{nullptr};
        std::size_t valid_lower_bits_unary{0};
    };

    [[nodiscard]] Reader reader() const { return Reader{data}; }

  private:
    Uint64Sequence data;

    friend std::ostream& operator<<(std::ostream& os, const GolombRiceVector& rbv) {
        os << rbv.data;
        return os;
    }

    friend std::istream& operator>>(std::istream& is, GolombRiceVector& rbv) {
        is >> rbv.data;
        return is;
    }
};

}  // namespace silkworm::succinct
