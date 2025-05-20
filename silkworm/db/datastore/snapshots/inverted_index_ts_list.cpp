// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "inverted_index_ts_list.hpp"

namespace silkworm::snapshots {

size_t InvertedIndexTimestampList::size() const {
    switch (static_cast<Alternative>(list_.index())) {
        case Alternative::kEmpty:
            return 0;
        case Alternative::kEliasFano:
            return ef_list().size();
        case Alternative::kSimple:
            return simple_list().size;
        default:
            SILKWORM_ASSERT(false);
    }
}

InvertedIndexTimestampList::value_type InvertedIndexTimestampList::SimpleList::at(size_t i) const {
    auto values = reinterpret_cast<const uint32_t*>(ByteView{data}.data() + offset);
    return base_timestamp + values[i];
}

InvertedIndexTimestampList::value_type InvertedIndexTimestampList::at(size_t i) const {
    switch (static_cast<Alternative>(list_.index())) {
        case Alternative::kEmpty:
            SILKWORM_ASSERT(false);
            return 0;
        case Alternative::kEliasFano:
            return ef_list().at(i);
        case Alternative::kSimple:
            return simple_list().at(i);
        default:
            SILKWORM_ASSERT(false);
            return 0;
    }
}

std::optional<InvertedIndexTimestampList::SeekResult> InvertedIndexTimestampList::SimpleList::seek(value_type value, bool reverse) const {
    const auto& list = *this;
    if (!reverse) {
        for (size_t i = 0; i < list.size; ++i) {
            value_type current_value = at(i);
            if (current_value >= value)
                return SeekResult{i, current_value};
        }
        return std::nullopt;
    } else {  // NOLINT(readability-else-after-return)
        for (size_t j = 0; j < list.size; ++j) {
            size_t i = list.size - 1 - j;
            value_type current_value = at(i);
            if (current_value <= value)
                return SeekResult{i, current_value};
        }
        return std::nullopt;
    }
}

std::optional<InvertedIndexTimestampList::SeekResult> InvertedIndexTimestampList::seek(value_type value, bool reverse) const {
    switch (static_cast<Alternative>(list_.index())) {
        case Alternative::kEmpty:
            return std::nullopt;
        case Alternative::kEliasFano:
            return ef_list().seek(value, reverse);
        case Alternative::kSimple:
            return simple_list().seek(value, reverse);
        default:
            SILKWORM_ASSERT(false);
            return std::nullopt;
    }
}

}  // namespace silkworm::snapshots
