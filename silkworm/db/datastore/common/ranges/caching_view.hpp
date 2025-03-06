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
#include <optional>
#include <ranges>
#include <utility>

namespace silkworm::views {

/**
 * Like views::cache1 in Range-v3
 * https://ericniebler.github.io/range-v3/structranges_1_1views_1_1cache1__fn.html
 * https://stackoverflow.com/questions/67321666/generator-called-twice-in-c20-views-pipeline
 */
template <std::ranges::range TRange>
    requires std::movable<TRange>
class CachingView : public std::ranges::view_interface<CachingView<TRange>> {
  public:
    class Iterator {
      public:
        using RangeIterator = std::ranges::iterator_t<TRange>;
        using RangeSentinel = std::ranges::sentinel_t<TRange>;

        using value_type = typename RangeIterator::value_type;
        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = typename RangeIterator::difference_type;
        using reference = value_type&;
        using pointer = void;

        Iterator(
            RangeIterator it,
            RangeSentinel sentinel)
            : it_{std::move(it)},
              sentinel_{std::move(sentinel)} {}

        Iterator()
            requires(std::default_initializable<RangeIterator> && std::default_initializable<RangeSentinel>)
        = default;

        reference operator*() const {
            if (!cached_value_) {
                cached_value_.emplace(std::move(*it_));
            }
            return *cached_value_;
        }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            cached_value_ = std::nullopt;
            return *this;
        }

        friend bool operator==(const Iterator& it, const std::default_sentinel_t&) {
            return it.it_ == it.sentinel_;
        }
        friend bool operator!=(const Iterator& it, const std::default_sentinel_t&) {
            return it.it_ != it.sentinel_;
        }
        friend bool operator==(const std::default_sentinel_t&, const Iterator& it) {
            return it.sentinel_ == it.it_;
        }
        friend bool operator!=(const std::default_sentinel_t&, const Iterator& it) {
            return it.sentinel_ != it.it_;
        }

      private:
        RangeIterator it_;
        RangeSentinel sentinel_;
        mutable std::optional<value_type> cached_value_;
    };

    static_assert(std::input_iterator<Iterator>);

    explicit CachingView(TRange&& range)
        : range_{std::move(range)} {}

    CachingView()
        requires std::default_initializable<TRange>
    = default;

    CachingView(CachingView&&) = default;
    CachingView& operator=(CachingView&&) noexcept = default;

    Iterator begin() { return Iterator{std::ranges::begin(range_), std::ranges::end(range_)}; }
    std::default_sentinel_t end() const { return std::default_sentinel; }

  private:
    TRange range_;
};

struct CachingViewFactory {
    template <class TRange>
    constexpr CachingView<TRange> operator()(TRange&& range) const {
        return CachingView<TRange>{std::forward<TRange>(range)};
    }

    template <class TRange>
    friend constexpr CachingView<TRange> operator|(TRange&& range, const CachingViewFactory& caching) {
        return caching(std::forward<TRange>(range));
    }
};

inline constexpr CachingViewFactory caching;

}  // namespace silkworm::views
