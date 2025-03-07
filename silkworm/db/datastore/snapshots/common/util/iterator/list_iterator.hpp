/*
   Copyright 2024 The Silkworm Authors

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

#include <concepts>
#include <iterator>
#include <utility>
#include <vector>

namespace silkworm {

template <class TList>
concept IndexedListConcept = requires(const TList list) {
    typename TList::value_type;
    { list.size() } -> std::same_as<size_t>;
    requires requires(size_t i) { { list[i] } -> std::convertible_to<typename TList::value_type>; };
};

static_assert(IndexedListConcept<std::vector<int>>);

template </* IndexedListConcept */ class TList, typename TValue = typename TList::value_type>
class ListIterator {
  public:
    using value_type = TValue;
    using iterator_category [[maybe_unused]] = std::random_access_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type;

    ListIterator() = default;
    ListIterator(const TList& list, size_t i) : list_{&list}, i_{i} {}

    reference operator*() const { return (*list_)[i_]; }
    pointer operator->() const { return &(**this); }

    ListIterator operator++(int) { return std::exchange(*this, ++ListIterator{*this}); }
    ListIterator& operator++() {
        ++i_;
        return *this;
    }

    ListIterator operator--(int) { return std::exchange(*this, --ListIterator{*this}); }
    ListIterator& operator--() {
        --i_;
        return *this;
    }

    ListIterator operator+(size_t count) const { return {*list_, i_ + count}; }
    ListIterator& operator+=(size_t count) {
        i_ += count;
        return *this;
    }
    friend ListIterator operator+(size_t count, ListIterator it) { return {*it.list_, count + it.i_}; }
    reference operator[](size_t count) const { return *(*this + count); }

    ListIterator operator-(size_t count) const { return {*list_, i_ - count}; }
    ListIterator& operator-=(size_t count) {
        i_ -= count;
        return *this;
    }
    difference_type operator-(ListIterator other) const {
        return static_cast<difference_type>(i_) - static_cast<difference_type>(other.i_);
    }

    friend bool operator==(const ListIterator& lhs, const ListIterator& rhs) = default;
    friend bool operator!=(const ListIterator& lhs, const ListIterator& rhs) = default;
    friend bool operator<(const ListIterator& lhs, const ListIterator& rhs) { return lhs.i_ < rhs.i_; }
    friend bool operator<=(const ListIterator& lhs, const ListIterator& rhs) { return lhs.i_ <= rhs.i_; }
    friend bool operator>(const ListIterator& lhs, const ListIterator& rhs) { return lhs.i_ > rhs.i_; }
    friend bool operator>=(const ListIterator& lhs, const ListIterator& rhs) { return lhs.i_ >= rhs.i_; }

  private:
    const TList* list_{nullptr};
    size_t i_{0};
};

static_assert(std::random_access_iterator<ListIterator<std::vector<int>>>);

}  // namespace silkworm
