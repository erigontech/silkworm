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

#include "../common/encoding/sequence.hpp"

namespace silkworm::snapshots::elias_fano {

//! 32-bit Elias-Fano (EF) list that can be used to encode one monotone non-decreasing sequence
class EliasFanoList32 {
  public:
    using Uint64Sequence = silkworm::snapshots::encoding::Uint64Sequence;

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    static EliasFanoList32 from_encoded_data(std::span<const uint8_t> encoded_data);

    //! Create an empty new 32-bit EF list prepared for the given sequence size and max value
    EliasFanoList32(uint64_t count, uint64_t max_value);

    //! Create a new 32-bit EF list from an existing data sequence
    //! \param count
    //! \param max_value
    //! \param data the existing data sequence (portion exceeding the total words will be ignored)
    EliasFanoList32(uint64_t count, uint64_t max_value, std::span<const uint8_t> data);

    size_t size() const { return count_; }

    size_t max() const { return u_ - 1; }

    size_t min() const { return get(0); }

    const Uint64Sequence& data() const { return data_; }

    size_t encoded_data_size() const { return kCountLength + kULength + data_.size() * sizeof(uint64_t); }

    uint64_t get(uint64_t i) const;

    void add_offset(uint64_t offset);

    void build();

    friend std::ostream& operator<<(std::ostream& os, const EliasFanoList32& ef);

    bool operator==(const EliasFanoList32& other) const {
        return (count_ == other.count_) &&
               (u_ == other.u_) &&
               (data_ == other.data_);
    }

    static EliasFanoList32 empty_list() {
        return EliasFanoList32{};
    }

  private:
    EliasFanoList32() = default;

    uint64_t derive_fields();

    uint64_t jump_size_words() const;

    static constexpr size_t kCountLength{sizeof(uint64_t)};
    static constexpr size_t kULength{sizeof(uint64_t)};

    std::span<uint64_t> lower_bits_;
    std::span<uint64_t> upper_bits_;
    std::span<uint64_t> jump_;
    uint64_t lower_bits_mask_{0};
    uint64_t count_{0};
    //! The strict upper bound on the EF data points, i.e. max + 1
    uint64_t u_{0};
    uint64_t l_{0};
    uint64_t i_{0};
    Uint64Sequence data_;
};

}  // namespace silkworm::snapshots::elias_fano
