// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdlib>
#include <functional>
#include <iterator>
#include <ranges>
#include <type_traits>
#include <utility>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::views {

template <
    std::ranges::input_range Range1, std::ranges::input_range Range2,
    class Comp = std::ranges::less,
    class Proj1 = std::identity, class Proj2 = std::identity>
class MergeView : public std::ranges::view_interface<MergeView<Range1, Range2, Comp, Proj1, Proj2>> {
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
            Comp comp, Proj1 proj1, Proj2 proj2)
            : it1_{std::ranges::begin(range1)},
              sentinel1_{std::ranges::end(range1)},
              it2_{std::ranges::begin(range2)},
              sentinel2_{std::ranges::end(range2)},
              comp_{std::move(comp)},
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
            switch (selector_) {
                case 1:
                    ++it1_;
                    break;
                case 2:
                    ++it2_;
                    break;
                default:
                    SILKWORM_ASSERT(false);
                    return *this;
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
            bool is_gte = std::invoke(comp_, std::invoke(proj2_, *it2_), std::invoke(proj1_, *it1_));
            return is_gte ? 2 : 1;
        }

        Range1Iterator it1_;
        Range1Sentinel sentinel1_;
        Range2Iterator it2_;
        Range2Sentinel sentinel2_;
        Comp comp_;
        Proj1 proj1_;
        Proj2 proj2_;
        char selector_{0};
    };

    static_assert(std::input_iterator<Iterator>);

    MergeView(
        Range1 range1, Range2 range2,
        Comp comp, Proj1 proj1, Proj2 proj2)
        : range1_{std::move(range1)},
          range2_{std::move(range2)},
          comp_{std::move(comp)},
          proj1_{std::move(proj1)},
          proj2_{std::move(proj2)} {}
    MergeView() = default;

    MergeView(MergeView&&) = default;
    MergeView& operator=(MergeView&&) noexcept = default;

    Iterator begin() { return Iterator{range1_, range2_, comp_, proj1_, proj2_}; }
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
    class Comp = std::ranges::less,
    class Proj1 = std::identity, class Proj2 = std::identity>
MergeView<Range1, Range2, Comp, Proj1, Proj2> merge(
    Range1&& v1, Range2&& v2,
    Comp comp = {}, Proj1 proj1 = {}, Proj2 proj2 = {}) {
    return MergeView<Range1, Range2, Comp, Proj1, Proj2>{
        std::forward<Range1>(v1),
        std::forward<Range2>(v2),
        std::move(comp),
        std::move(proj1),
        std::move(proj2),
    };
}

}  // namespace silkworm::views
