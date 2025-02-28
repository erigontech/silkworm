/*
   Copyright 2025 The Silkworm Authors

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
