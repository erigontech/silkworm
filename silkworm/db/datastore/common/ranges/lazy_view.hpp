// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>
#include <ranges>

namespace silkworm::ranges {

template <std::invocable TRangeFactory, std::ranges::range TRange = decltype(std::invoke(std::declval<TRangeFactory>()))>
class LazyView : public std::ranges::view_interface<LazyView<TRangeFactory, TRange>> {
  public:
    LazyView() = default;

    explicit LazyView(TRangeFactory&& range_factory) : range_factory_{std::move(range_factory)} {}

    LazyView(LazyView&&) = default;

    LazyView& operator=(LazyView&& other) noexcept {
        range_factory_ = std::exchange(std::move(other.range_factory_), std::nullopt);
        range_ = std::exchange(std::move(other.range_), std::nullopt);
        return this;
    };

    std::ranges::iterator_t<TRange> begin() { return std::ranges::begin(range()); }
    std::ranges::sentinel_t<TRange> end() { return std::ranges::end(range()); }

  private:
    TRange& range() {
        if (!range_) {
            range_.emplace(std::invoke(*range_factory_));
        }
        return *range_;
    }

    std::optional<TRangeFactory> range_factory_;
    std::optional<TRange> range_;
};

template <class TRangeFactory>
LazyView<TRangeFactory> lazy(TRangeFactory&& range_factory) {
    return LazyView<TRangeFactory>{std::forward<TRangeFactory>(range_factory)};
}

}  // namespace silkworm::ranges
