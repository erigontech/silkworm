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

#include <optional>
#include <ranges>
#include <utility>

#include <silkworm/core/common/assert.hpp>

// std::views::concat is present on C++26
#if __cplusplus >= 202601L
#define SILKWORM_HAS_BUILTIN_CONCAT_VIEW
#endif

#ifdef SILKWORM_HAS_BUILTIN_CONCAT_VIEW
namespace silkworm::views::concat_view::builtin {

template <std::ranges::input_range... Views>
using ConcatView = std::ranges::concat_view<Views...>;

}  // namespace silkworm::views::concat_view::builtin
#endif

namespace silkworm::views::concat_view::fallback {

template <std::ranges::input_range Range1, std::ranges::input_range Range2>
class ConcatView : public std::ranges::view_interface<ConcatView<Range1, Range2>> {
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
        Iterator(Range1* range1, Range2* range2)
            : range1_{range1},
              range2_{range2},
              it1_{std::ranges::begin(*range1_)},
              sentinel1_{std::ranges::end(*range1_)} {
            if (*it1_ == *sentinel1_) {
                it1_ = std::nullopt;
                sentinel1_ = std::nullopt;
                it2_ = std::ranges::begin(*range2_);
                sentinel2_ = std::ranges::end(*range2_);
                if (*it2_ == *sentinel2_) {
                    it2_ = std::nullopt;
                    sentinel2_ = std::nullopt;
                }
            }
        }

        reference operator*() const {
            if (it1_) return **it1_;
            if (it2_) return **it2_;
            SILKWORM_ASSERT(false);
            std::abort();
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            if (it1_) {
                ++(*it1_);
                if (*it1_ == *sentinel1_) {
                    it1_ = std::nullopt;
                    sentinel1_ = std::nullopt;
                    it2_ = std::ranges::begin(*range2_);
                    sentinel2_ = std::ranges::end(*range2_);
                    if (*it2_ == *sentinel2_) {
                        it2_ = std::nullopt;
                        sentinel2_ = std::nullopt;
                    }
                }
            } else if (it2_) {
                ++(*it2_);
#if defined(__GNUC__) && __GNUC__ < 12 && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
                if (*it2_ == *sentinel2_) {
#if defined(__GNUC__) && __GNUC__ < 12 && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
                    it2_ = std::nullopt;
                    sentinel2_ = std::nullopt;
                }
            }
            return *this;
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return !it.it1_ && !it.it2_;
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t&) {
            return it.it1_ || it.it2_;
        }
        friend bool operator==(const std::default_sentinel_t& s, const Iterator& it) {
            return it == s;
        }
        friend bool operator!=(const std::default_sentinel_t& s, const Iterator& it) {
            return it != s;
        }

      private:
        Range1* range1_{nullptr};
        Range2* range2_{nullptr};
        std::optional<Range1Iterator> it1_;
        std::optional<Range2Iterator> it2_;
        std::optional<Range1Sentinel> sentinel1_;
        std::optional<Range2Sentinel> sentinel2_;
    };

    static_assert(std::input_iterator<Iterator>);

    ConcatView(Range1 range1, Range2 range2)
        : range1_{std::move(range1)},
          range2_{std::move(range2)} {}
    ConcatView() = default;

    ConcatView(ConcatView&&) = default;
    ConcatView& operator=(ConcatView&&) noexcept = default;

    Iterator begin() { return Iterator{&range1_, &range2_}; }
    std::default_sentinel_t end() const { return std::default_sentinel; }

  private:
    Range1 range1_;
    Range2 range2_;
};

}  // namespace silkworm::views::concat_view::fallback

namespace silkworm::views {

#ifdef SILKWORM_HAS_BUILTIN_CONCAT_VIEW
using silkworm::views::concat_view::builtin::ConcatView;
#else
using silkworm::views::concat_view::fallback::ConcatView;
#endif

template <class Range1, class Range2>
auto concat(Range1&& v1, Range2&& v2) {
    return ConcatView<Range1, Range2>{std::forward<Range1>(v1), std::forward<Range2>(v2)};
}

}  // namespace silkworm::views
