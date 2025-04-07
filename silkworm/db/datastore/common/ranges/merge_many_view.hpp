// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <compare>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <optional>
#include <ranges>
#include <type_traits>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>

#include "merge_compare_func.hpp"
#include "vector_from_range.hpp"

namespace silkworm::views {

template <
    std::ranges::input_range Ranges,
    std::ranges::input_range Range = std::iter_value_t<std::ranges::iterator_t<Ranges>>,
    class Comp = MergeCompareFunc,
    class Proj = std::identity,
    bool kUnique = false>
class MergeManyView : public std::ranges::view_interface<MergeManyView<Range, Ranges, Comp, Proj, kUnique>> {
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
            : ranges_{vector_from_range(ranges)},
              comp_{comp},
              proj_{std::move(proj)} {
            for (Range& range : ranges_) {
                iterators_.emplace_back(std::ranges::begin(range));
                sentinels_.emplace_back(std::ranges::end(range));
            }

            for (size_t i = 0; i < iterators_.size(); i++) {
                if (!it_ended(i)) {
                    order_.push_back(i);
                }
            }
            std::ranges::make_heap(order_, order_compare_func());

            advance();
        }

        reference operator*() const {
            SILKWORM_ASSERT(current_value_);
            return *current_value_;
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            advance();
            return *this;
        }

        void advance() {
            if (order_.empty()) {
                current_value_.reset();
                return;
            }

            current_value_.emplace(move_it_value(order_.front()));

            if constexpr (!kUnique) {
                next();
                return;
            }

            // grab the current key for duplicate detection
            const auto& current_key = std::invoke(proj_, *current_value_);

            // first iteration: increment the current iterator once and restore the order
            // next iterations: skip duplicate keys and restore the order
            do {
                next();
            } while (
                !order_.empty() &&
                std::is_eq(std::invoke(*comp_, std::invoke(proj_, *iterators_[order_.front()]), current_key)));
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return !it.current_value_.has_value();
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t&) {
            return it.current_value_.has_value();
        }
        friend bool operator==(const std::default_sentinel_t& s, const Iterator& it) {
            return it == s;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Iterator& it) {
            return it != s;
        }

      private:
        //! Increment the current iterator once and restore the order
        void next() {
            size_t current = order_.front();
            ++iterators_[current];

            std::ranges::pop_heap(order_, order_compare_func());
            order_.pop_back();

            if (!it_ended(current)) {
                order_.push_back(current);
                std::ranges::push_heap(order_, order_compare_func());
            }
        }

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

        value_type move_it_value(size_t i) {
            return std::ranges::iter_move(iterators_[i]);
        }

        std::vector<Range> ranges_;
        std::vector<RangeIterator> iterators_;
        std::vector<RangeSentinel> sentinels_;
        const Comp* comp_{nullptr};
        Proj proj_;
        std::vector<size_t> order_;
        mutable std::optional<value_type> current_value_;
    };

    static_assert(std::input_iterator<Iterator>);

    MergeManyView(
        Ranges ranges,
        Comp comp, Proj proj)
        : ranges_{std::move(ranges)},
          comp_{std::move(comp)},
          proj_{std::move(proj)} {}
    MergeManyView() = default;

    MergeManyView(MergeManyView&&) = default;
    MergeManyView& operator=(MergeManyView&&) noexcept = default;

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
    class Comp = MergeCompareFunc,
    class Proj = std::identity>
MergeManyView<Ranges, Range, Comp, Proj> merge_many(
    Ranges&& ranges,
    Comp comp = {}, Proj proj = {}) {
    return MergeManyView<Ranges, Range, Comp, Proj>{
        std::forward<Ranges>(ranges),
        std::move(comp),
        std::move(proj),
    };
}

template <
    class Ranges,
    class Range = std::iter_value_t<std::ranges::iterator_t<Ranges>>,
    class Comp = MergeCompareFunc,
    class Proj = std::identity>
MergeManyView<Ranges, Range, Comp, Proj, /* kUnique = */ true> merge_unique_many(
    Ranges&& ranges,
    Comp comp = {}, Proj proj = {}) {
    return MergeManyView<Ranges, Range, Comp, Proj, /* kUnique = */ true>{
        std::forward<Ranges>(ranges),
        std::move(comp),
        std::move(proj),
    };
}

}  // namespace silkworm::views
