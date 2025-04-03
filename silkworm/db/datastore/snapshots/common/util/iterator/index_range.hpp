// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "list_iterator.hpp"

namespace silkworm {

struct IndexRange {
    using value_type = size_t;

    size_t start_index{0};
    size_t end_index{0};

    size_t size() const { return end_index - start_index; }
    size_t operator[](size_t i) const { return i; }

    using Iterator = ListIterator<IndexRange, size_t>;
    Iterator begin() const { return Iterator{*this, start_index}; }
    Iterator end() const { return Iterator{*this, end_index}; }
};

static_assert(IndexedListConcept<IndexRange>);

}  // namespace silkworm
