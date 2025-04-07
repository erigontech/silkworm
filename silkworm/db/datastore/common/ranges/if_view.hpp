// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdlib>
#include <iterator>
#include <optional>
#include <ranges>
#include <type_traits>
#include <utility>

#include <silkworm/core/common/assert.hpp>

namespace silkworm::views {

template <std::ranges::input_range Range1, std::ranges::input_range Range2>
class IfView : public std::ranges::view_interface<IfView<Range1, Range2>> {
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
            std::optional<Range1Iterator> it1,
            std::optional<Range1Sentinel> sentinel1,
            std::optional<Range2Iterator> it2,
            std::optional<Range2Sentinel> sentinel2)
            : it1_{std::move(it1)},
              sentinel1_{std::move(sentinel1)},
              it2_{std::move(it2)},
              sentinel2_{std::move(sentinel2)} {}

        reference operator*() const {
            if (it1_) return **it1_;
            if (it2_) return **it2_;
            SILKWORM_ASSERT(false);
            std::abort();
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            if (it1_) ++(*it1_);
            if (it2_) ++(*it2_);
            return *this;
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return (it.it1_ && (*it.it1_ == *it.sentinel1_)) ||
                   (it.it2_ && (*it.it2_ == *it.sentinel2_));
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t& s) {
            return !(it == s);
        }
        friend bool operator==(const std::default_sentinel_t& s, const Iterator& it) {
            return it == s;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Iterator& it) {
            return !(it == s);
        }

      private:
        std::optional<Range1Iterator> it1_;
        std::optional<Range1Sentinel> sentinel1_;
        std::optional<Range2Iterator> it2_;
        std::optional<Range2Sentinel> sentinel2_;
    };

    static_assert(std::input_iterator<Iterator>);

    IfView(bool cond, Range1 range1, Range2 range2)
        : cond_{cond},
          range1_{std::move(range1)},
          range2_{std::move(range2)} {}
    IfView() = default;

    IfView(IfView&&) = default;
    IfView& operator=(IfView&&) noexcept = default;

    Iterator begin() {
        if (cond_) {
            return Iterator{
                std::ranges::begin(range1_),
                std::ranges::end(range1_),
                std::nullopt,
                std::nullopt,
            };
        } else {
            return Iterator{
                std::nullopt,
                std::nullopt,
                std::ranges::begin(range2_),
                std::ranges::end(range2_),
            };
        }
    }

    std::default_sentinel_t end() const { return std::default_sentinel; }

  private:
    bool cond_{false};
    Range1 range1_;
    Range2 range2_;
};

template <class Range1, class Range2>
IfView<Range1, Range2> if_view(bool cond, Range1&& v1, Range2&& v2) {
    return IfView<Range1, Range2>{cond, std::forward<Range1>(v1), std::forward<Range2>(v2)};
}

}  // namespace silkworm::views
