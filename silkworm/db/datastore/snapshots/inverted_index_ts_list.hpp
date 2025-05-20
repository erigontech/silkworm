// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <span>
#include <utility>
#include <variant>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "../common/timestamp.hpp"
#include "elias_fano/elias_fano_list.hpp"

namespace silkworm::snapshots {

class InvertedIndexTimestampList {
  public:
    using value_type = datastore::Timestamp;

    InvertedIndexTimestampList() : list_{std::monostate{}} {}
    explicit InvertedIndexTimestampList(elias_fano::EliasFanoList32 list) : list_{std::move(list)} {}

    using SeekResult = std::pair<size_t, value_type>;

    struct SimpleList {
        BytesOrByteView data;
        value_type base_timestamp;
        size_t offset;
        size_t size;

        value_type at(size_t i) const;
        value_type operator[](size_t i) const { return at(i); }
        std::optional<SeekResult> seek(value_type value, bool reverse) const;
    };

    InvertedIndexTimestampList(BytesOrByteView data, value_type base_timestamp, size_t offset, size_t size)
        : list_{
              SimpleList{
                  std::move(data),
                  base_timestamp,
                  offset,
                  size,
              },
          } {
        SILKWORM_ASSERT(ByteView{data}.size() >= offset + size * sizeof(uint32_t));
    }

    size_t size() const;

    value_type at(size_t i) const;
    value_type operator[](size_t i) const { return at(i); }

    //! Find the first index where at(i) >= value if reverse = false.
    //! Find the last index where at(i) <= value if reverse = true.
    //! \return (i, value) or nullopt if not found
    std::optional<SeekResult> seek(value_type value, bool reverse = false) const;

    using Iterator = ListIterator<InvertedIndexTimestampList>;
    Iterator begin() const { return Iterator{*this, 0}; }
    Iterator end() const { return Iterator{*this, size()}; }

  private:
    enum class Alternative : size_t {
        kEmpty,
        kEliasFano,
        kSimple,
    };

    const elias_fano::EliasFanoList32& ef_list() const {
        return std::get<elias_fano::EliasFanoList32>(list_);
    }

    const SimpleList& simple_list() const {
        return std::get<SimpleList>(list_);
    }

    std::variant<std::monostate, elias_fano::EliasFanoList32, SimpleList> list_;
};

}  // namespace silkworm::snapshots
