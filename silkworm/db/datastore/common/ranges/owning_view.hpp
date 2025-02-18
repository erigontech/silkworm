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

#include <ranges>

// std::ranges::owning_view is not present on GCC < 12.1
// see P2415R2 at https://gcc.gnu.org/onlinedocs/libstdc++/manual/status.html#status.iso.2020
#if __GNUC__ < 12 && !defined(__clang__)
#else
#define SILKWORM_HAS_BUILTIN_OWNING_VIEW
#endif

#ifdef SILKWORM_HAS_BUILTIN_OWNING_VIEW
namespace silkworm::ranges::builtin {

template <std::ranges::range TRange>
using OwningView = std::ranges::owning_view<TRange>;

}  // namespace silkworm::ranges::builtin
#endif

namespace silkworm::ranges::fallback {

// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2021/p2415r2.html
template <std::ranges::range TRange>
    requires std::movable<TRange>
class OwningView : public std::ranges::view_interface<OwningView<TRange>> {
  public:
    OwningView()
        requires std::default_initializable<TRange>
    = default;

    explicit constexpr OwningView(TRange&& range) : range_{std::move(range)} {}

    OwningView(OwningView&&) = default;
    OwningView& operator=(OwningView&&) = default;

    constexpr TRange& base() & noexcept { return range_; }
    constexpr const TRange& base() const& noexcept { return range_; }
    constexpr TRange&& base() && noexcept { return std::move(range_); }
    constexpr const TRange&& base() const&& noexcept { return std::move(range_); }

    constexpr std::ranges::iterator_t<TRange> begin() { return std::ranges::begin(range_); }
    constexpr std::ranges::sentinel_t<TRange> end() { return std::ranges::end(range_); }

    constexpr auto begin() const
        requires std::ranges::range<const TRange>
    { return std::ranges::begin(range_); }

    constexpr auto end() const
        requires std::ranges::range<const TRange>
    { return std::ranges::end(range_); }

    constexpr bool empty()
        requires requires { std::ranges::empty(std::declval<TRange>()); }
    { return std::ranges::empty(range_); }

    constexpr bool empty() const
        requires requires { std::ranges::empty(std::declval<const TRange>()); }
    { return std::ranges::empty(range_); }

    constexpr auto size()
        requires std::ranges::sized_range<TRange>
    { return std::ranges::size(range_); }

    constexpr auto size() const
        requires std::ranges::sized_range<const TRange>
    { return std::ranges::size(range_); }

    constexpr auto data()
        requires std::ranges::contiguous_range<TRange>
    { return std::ranges::data(range_); }

    constexpr auto data() const
        requires std::ranges::contiguous_range<const TRange>
    { return std::ranges::data(range_); }

  private:
    TRange range_;
};

}  // namespace silkworm::ranges::fallback

namespace silkworm::ranges {

#ifdef SILKWORM_HAS_BUILTIN_OWNING_VIEW
using silkworm::ranges::builtin::OwningView;
#else
using silkworm::ranges::fallback::OwningView;
#endif

template <class TRange>
auto owning_view(TRange&& range) {
    return OwningView<TRange>{std::forward<TRange>(range)};
}

}  // namespace silkworm::ranges
