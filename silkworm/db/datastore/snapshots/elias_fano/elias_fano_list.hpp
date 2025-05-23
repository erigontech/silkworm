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

#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <utility>

#include <silkworm/core/common/bytes.hpp>

#include "../common/encoding/sequence.hpp"
#include "../common/util/iterator/list_iterator.hpp"

namespace silkworm::snapshots::elias_fano {

//! 32-bit Elias-Fano (EF) list reader that can be used to decode one monotone non-decreasing sequence
class EliasFanoList32 {
  public:
    using value_type = uint64_t;

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    static EliasFanoList32 from_encoded_data(BytesOrByteView encoded_data_holder);

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    static EliasFanoList32 from_encoded_data(std::span<const uint8_t> encoded_data);

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    static EliasFanoList32 from_encoded_data(ByteView encoded_data);

    //! Create a new 32-bit EF list from the given encoded data (i.e. data plus data header)
    //! @warning using this factory method will hold a copy of encoded data in data_holder_
    static EliasFanoList32 from_encoded_data(Bytes encoded_data);

    //! Create a new 32-bit EF list from an existing data sequence
    //! \param count
    //! \param max_value
    //! \param data_offset offset in the data_holder to the data sequence
    //! \param data_holder the data (portion exceeding the total words will be ignored)
    EliasFanoList32(
        uint64_t count,
        uint64_t max_value,
        uint64_t data_offset,
        BytesOrByteView data_holder);

    size_t size() const { return count_; }

    uint64_t max() const { return u_ - 1; }

    uint64_t min() const { return at(0); }

    std::span<const uint64_t> data() const {
        const uint64_t* data = reinterpret_cast<const uint64_t*>(ByteView{data_holder_}.data() + data_offset_);
        return {data, total_words_};
    }

    size_t encoded_data_size() const { return kCountLength + kULength + total_words_ * sizeof(uint64_t); }

    uint64_t at(size_t i) const;
    uint64_t operator[](size_t i) const { return at(i); }

    //! Find the first index where at(i) >= value if reverse = false.
    //! Find the last index where at(i) <= value if reverse = true.
    //! \return (i, value) or nullopt if not found
    std::optional<std::pair<size_t, uint64_t>> seek(uint64_t value, bool reverse = false) const;

    friend std::ostream& operator<<(std::ostream& os, const EliasFanoList32& ef);

    bool operator==(const EliasFanoList32& other) const {
        return (count_ == other.count_) && (u_ == other.u_) && std::ranges::equal(data(), other.data());
    }

    static uint64_t total_words(uint64_t count, uint64_t max_value);
    static uint64_t jump_size_words(uint64_t count);

    using Iterator = ListIterator<EliasFanoList32, value_type>;
    Iterator begin() const { return Iterator{*this, 0}; }
    Iterator end() const { return Iterator{*this, size()}; }

  private:
    uint64_t upper(uint64_t i) const;
    uint64_t derive_fields();

    static constexpr size_t kCountLength{sizeof(uint64_t)};
    static constexpr size_t kULength{sizeof(uint64_t)};

    std::span<const uint64_t> lower_bits_{};
    std::span<const uint64_t> upper_bits_{};
    std::span<const uint64_t> jump_{};
    uint64_t lower_bits_mask_{0};
    uint64_t count_{0};
    //! The strict upper bound on the EF data points, i.e. max + 1
    uint64_t u_{0};
    uint64_t l_{0};
    uint64_t data_offset_{0};
    uint64_t total_words_{0};
    //! The EF encoded data sequence
    BytesOrByteView data_holder_{};
};

//! 32-bit Elias-Fano (EF) list writer that can be used to encode one monotone non-decreasing sequence
class EliasFanoList32Builder {
  public:
    using Uint64Sequence = silkworm::snapshots::encoding::Uint64Sequence;

    //! Create an empty new 32-bit EF list prepared for the given sequence size and max value
    EliasFanoList32Builder(uint64_t count, uint64_t max_value);

    friend std::ostream& operator<<(std::ostream& os, const EliasFanoList32Builder& ef);

    bool operator==(const EliasFanoList32Builder& other) const {
        return (count_ == other.count_) &&
               (u_ == other.u_) &&
               (data_ == other.data_);
    }

    EliasFanoList32 as_view() const {
        const auto max_value = u_ - 1;
        return EliasFanoList32{
            count_,
            max_value,
            0,
            BytesOrByteView{ByteView{reinterpret_cast<const uint8_t*>(data_.data()), EliasFanoList32::total_words(count_, max_value) * sizeof(uint64_t)}},
        };
    };

    size_t size() const { return count_; }

    void add_offset(uint64_t offset);
    void push_back(uint64_t offset) { add_offset(offset); }

    void build();

  private:
    uint64_t derive_fields();

    std::span<uint64_t> lower_bits_{};
    std::span<uint64_t> upper_bits_{};
    std::span<uint64_t> jump_{};
    uint64_t lower_bits_mask_{0};
    uint64_t count_{0};
    //! The strict upper bound on the EF data points, i.e. max + 1
    uint64_t u_{0};
    uint64_t l_{0};
    uint64_t i_{0};
    Uint64Sequence data_;
};

}  // namespace silkworm::snapshots::elias_fano
