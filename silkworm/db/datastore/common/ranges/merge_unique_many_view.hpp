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

#include <algorithm>
#include <compare>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>

#include "merge_unique_compare_func.hpp"

namespace silkworm::views {

template <
    std::ranges::input_range Ranges,
    std::ranges::input_range Range = std::iter_value_t<std::ranges::iterator_t<Ranges>>,
    class Comp = MergeUniqueCompareFunc,
    class Proj = std::identity>
class MergeUniqueManyView : public std::ranges::view_interface<MergeUniqueManyView<Range, Ranges, Comp, Proj>> {
  public:
    class Iterator {
      public:
        using RangeIterator = std::ranges::iterator_t<Range>;
        using RangeSentinel = std::ranges::sentinel_t<Range>;
        using RangeReferenceType = std::iter_reference_t<RangeIterator>;
        using DereferenceType = RangeReferenceType;

        using value_type = std::iter_value_t<RangeIterator>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::iter_difference_t<RangeIterator>;
        using reference = DereferenceType;
        using pointer = std::remove_reference_t<reference>*;

        Iterator() = default;
        Iterator(
            Ranges& ranges,
            const Comp* comp, Proj proj)
            : comp_{comp},
              proj_{std::move(proj)} {
            for (auto&& range : ranges) {
                iterators_.emplace_back(std::ranges::begin(range));
                sentinels_.emplace_back(std::ranges::end(range));
            }

            for (size_t i = 0; i < iterators_.size(); i++) {
                if (!it_ended(i)) {
                    order_.push_back(i);
                }
            }
            std::ranges::make_heap(order_, order_compare_func());
        }

        reference operator*() const {
            if (order_.empty()) {
                SILKWORM_ASSERT(false);
                std::abort();
            }
            auto& it = iterators_[order_.front()];
            return *it;
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            // backup the current key for duplicate detection
            auto current_key = std::invoke(proj_, **this);

            // first iteration: increment the current iterator once and restore the order
            // next iterations: skip duplicate keys and restore the order
            do {
                size_t current = order_.front();
                ++iterators_[current];

                std::ranges::pop_heap(order_, order_compare_func());
                order_.pop_back();

                if (!it_ended(current)) {
                    order_.push_back(current);
                    std::ranges::push_heap(order_, order_compare_func());
                }
            } while (
                !order_.empty() &&
                std::is_eq(std::invoke(*comp_, std::invoke(proj_, *iterators_[order_.front()]), current_key)));

            return *this;
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return it.order_.empty();
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t&) {
            return !it.order_.empty();
        }
        friend bool operator==(const std::default_sentinel_t& s, const Iterator& it) {
            return it == s;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Iterator& it) {
            return it != s;
        }

      private:
        bool it_ended(size_t i) const {
            return iterators_[i] == sentinels_[i];
        }

        bool less(size_t lhs, size_t rhs) const {
            const RangeIterator& lhs_it = iterators_[lhs];
            const RangeIterator& rhs_it = iterators_[rhs];
            std::partial_ordering comp_result = std::invoke(*comp_, std::invoke(proj_, *lhs_it), std::invoke(proj_, *rhs_it));
            if (std::is_lt(comp_result)) return true;
            if (std::is_gt(comp_result)) return false;
            // if equal prefer the smallest index range
            return lhs < rhs;
        }

        auto order_compare_func() const {
            return [this](size_t lhs, size_t rhs) -> bool {
                // the order is reversed because the heap puts the largest element at the front
                // (according to this->order_compare_func() as its "less" predicate),
                // but the merge sequence is expected to produce the smallest element at the front
                // (according to this->less() predicate)
                return this->less(rhs, lhs);
            };
        }

        std::vector<RangeIterator> iterators_;
        std::vector<RangeSentinel> sentinels_;
        const Comp* comp_{nullptr};
        Proj proj_;
        std::vector<size_t> order_;
    };

    static_assert(std::input_iterator<Iterator>);

    MergeUniqueManyView(
        Ranges ranges,
        Comp comp, Proj proj)
        : ranges_{std::move(ranges)},
          comp_{std::move(comp)},
          proj_{std::move(proj)} {}
    MergeUniqueManyView() = default;

    MergeUniqueManyView(MergeUniqueManyView&&) = default;
    MergeUniqueManyView& operator=(MergeUniqueManyView&&) noexcept = default;

    Iterator begin() { return Iterator{ranges_, &comp_, proj_}; }
    std::default_sentinel_t end() const { return std::default_sentinel; }

  private:
    Ranges ranges_;
    Comp comp_;
    Proj proj_;
};

template <
    class Ranges,
    class Range = std::iter_value_t<std::ranges::iterator_t<Ranges>>,
    class Comp = MergeUniqueCompareFunc,
    class Proj = std::identity>
MergeUniqueManyView<Ranges, Range, Comp, Proj> merge_unique_many(
    Ranges&& ranges,
    Comp comp = {}, Proj proj = {}) {
    return MergeUniqueManyView<Ranges, Range, Comp, Proj>{
        std::forward<Ranges>(ranges),
        std::move(comp),
        std::move(proj),
    };
}

}  // namespace silkworm::views
