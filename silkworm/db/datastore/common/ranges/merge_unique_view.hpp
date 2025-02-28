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

#include <compare>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>

#include <silkworm/core/common/assert.hpp>

#include "merge_compare_func.hpp"

namespace silkworm::views {

template <
    std::ranges::input_range Range1, std::ranges::input_range Range2,
    class Comp = MergeCompareFunc,
    class Proj1 = std::identity, class Proj2 = std::identity>
class MergeUniqueView : public std::ranges::view_interface<MergeUniqueView<Range1, Range2, Comp, Proj1, Proj2>> {
  public:
    class Iterator {
      public:
        using Range1Iterator = std::ranges::iterator_t<Range1>;
        using Range1Sentinel = std::ranges::sentinel_t<Range1>;
        using Range1ReferenceType = std::iter_reference_t<Range1Iterator>;
        using Range2Iterator = std::ranges::iterator_t<Range2>;
        using Range2Sentinel = std::ranges::sentinel_t<Range2>;
        using Range2ReferenceType = std::iter_reference_t<Range2Iterator>;
        using DereferenceType = std::conditional_t<!std::is_reference_v<Range1ReferenceType>, Range1ReferenceType, Range2ReferenceType>;

        using value_type = std::iter_value_t<Range1Iterator>;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::iter_difference_t<Range1Iterator>;
        using reference = DereferenceType;
        using pointer = std::remove_reference_t<reference>*;

        Iterator() = default;
        Iterator(
            Range1& range1, Range2& range2,
            const Comp* comp, Proj1 proj1, Proj2 proj2)
            : it1_{std::ranges::begin(range1)},
              sentinel1_{std::ranges::end(range1)},
              it2_{std::ranges::begin(range2)},
              sentinel2_{std::ranges::end(range2)},
              comp_{comp},
              proj1_{std::move(proj1)},
              proj2_{std::move(proj2)} {
            selector_ = select(it1_ended(), it2_ended());
        }

        reference operator*() const {
            switch (selector_) {
                case 1:
                    return *it1_;
                case 2:
                    return *it2_;
                default:
                    SILKWORM_ASSERT(false);
                    std::abort();
            }
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            if (selector_ == 0) {
                SILKWORM_ASSERT(false);
                return *this;
            }

            // backup the current key for duplicate detection
            auto current_key = (selector_ == 1) ? std::invoke(proj1_, *it1_) : std::invoke(proj2_, *it2_);

            // increment the current iterator once
            if (selector_ == 1) {
                ++it1_;
            } else {
                ++it2_;
            }

            // skip duplicate keys
            while (!it1_ended() && std::is_eq(std::invoke(*comp_, std::invoke(proj1_, *it1_), current_key))) {
                ++it1_;
            }
            while (!it2_ended() && std::is_eq(std::invoke(*comp_, std::invoke(proj2_, *it2_), current_key))) {
                ++it2_;
            }

            selector_ = select(it1_ended(), it2_ended());
            return *this;
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return !it.selector_;
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t&) {
            return it.selector_;
        }
        friend bool operator==(const std::default_sentinel_t& s, const Iterator& it) {
            return it == s;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Iterator& it) {
            return it != s;
        }

      private:
        bool it1_ended() const {
            return it1_ == sentinel1_;
        }
        bool it2_ended() const {
            return it2_ == sentinel2_;
        }
        char select(bool it1_ended, bool it2_ended) const {
            if (it1_ended && it2_ended) return 0;
            if (it1_ended) return 2;
            if (it2_ended) return 1;
            std::partial_ordering comp_result = std::invoke(*comp_, std::invoke(proj1_, *it1_), std::invoke(proj2_, *it2_));
            if (std::is_lt(comp_result)) return 1;
            if (std::is_gt(comp_result)) return 2;
            // if equal prefer the first range
            return 1;
        }

        Range1Iterator it1_;
        Range1Sentinel sentinel1_;
        Range2Iterator it2_;
        Range2Sentinel sentinel2_;
        const Comp* comp_{nullptr};
        Proj1 proj1_;
        Proj2 proj2_;
        char selector_{0};
    };

    static_assert(std::input_iterator<Iterator>);

    MergeUniqueView(
        Range1 range1, Range2 range2,
        Comp comp, Proj1 proj1, Proj2 proj2)
        : range1_{std::move(range1)},
          range2_{std::move(range2)},
          comp_{std::move(comp)},
          proj1_{std::move(proj1)},
          proj2_{std::move(proj2)} {}
    MergeUniqueView() = default;

    MergeUniqueView(MergeUniqueView&&) = default;
    MergeUniqueView& operator=(MergeUniqueView&&) noexcept = default;

    Iterator begin() { return Iterator{range1_, range2_, &comp_, proj1_, proj2_}; }
    std::default_sentinel_t end() const { return std::default_sentinel; }

  private:
    Range1 range1_;
    Range2 range2_;
    Comp comp_;
    Proj1 proj1_;
    Proj2 proj2_;
};

template <
    class Range1, class Range2,
    class Comp = MergeCompareFunc,
    class Proj1 = std::identity, class Proj2 = std::identity>
MergeUniqueView<Range1, Range2, Comp, Proj1, Proj2> merge_unique(
    Range1&& v1, Range2&& v2,
    Comp comp = {}, Proj1 proj1 = {}, Proj2 proj2 = {}) {
    return MergeUniqueView<Range1, Range2, Comp, Proj1, Proj2>{
        std::forward<Range1>(v1),
        std::forward<Range2>(v2),
        std::move(comp),
        std::move(proj1),
        std::move(proj2),
    };
}

}  // namespace silkworm::views
