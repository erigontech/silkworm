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
#include <iostream>
#include <span>
#include <utility>

#include "../common/encoding/sequence.hpp"

namespace silkworm::snapshots::elias_fano {

//! 16-bit Double Elias-Fano list that used to encode *two* monotone non-decreasing sequences in RecSplit
class DoubleEliasFanoList16 {
  public:
    using Uint64Sequence = encoding::Uint64Sequence;

    DoubleEliasFanoList16() = default;

    const Uint64Sequence& data() const { return data_; }

    uint64_t num_buckets() const { return num_buckets_; }

    void build(const Uint64Sequence& cum_keys, const Uint64Sequence& position);

    void get2(uint64_t i, uint64_t& cum_keys, uint64_t& position) const;

    void get3(uint64_t i, uint64_t& cum_keys, uint64_t& cum_keys_next, uint64_t& position) const;

  private:
    std::pair<uint64_t, uint64_t> derive_fields();

    void get(
        const uint64_t i,
        uint64_t& cum_keys,
        uint64_t& position,
        uint64_t& window_cum_keys,
        uint64_t& select_cum_keys,
        uint64_t& curr_word_cum_keys,
        uint64_t& lower,
        uint64_t& cum_delta) const;

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

    size_t jump_size_words() const;

    friend std::ostream& operator<<(std::ostream& os, const DoubleEliasFanoList16& ef);

    friend std::istream& operator>>(std::istream& is, DoubleEliasFanoList16& ef);
};

}  // namespace silkworm::snapshots::elias_fano
