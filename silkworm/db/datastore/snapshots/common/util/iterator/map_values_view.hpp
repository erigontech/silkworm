// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iterator>
#include <map>
#include <ranges>
#include <unordered_map>
#include <utility>

#include <absl/container/flat_hash_map.h>

namespace silkworm::map_values_view::fallback {

template <typename TMapKey, typename TMapValue, class TMap>
class MapValuesView : public std::ranges::view_interface<MapValuesView<TMapKey, TMapValue, TMap>> {
  public:
    class Iterator {
      public:
        using value_type = TMapValue;
        using iterator_category [[maybe_unused]] = std::bidirectional_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = const value_type&;

        explicit Iterator(typename TMap::const_iterator it) : it_(it) {}
        Iterator() = default;

        reference operator*() const { return it_->second; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++() {
            ++it_;
            return *this;
        }

        Iterator operator--(int) { return std::exchange(*this, --Iterator{*this}); }
        Iterator& operator--() {
            --it_;
            return *this;
        }

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs) = default;

      private:
        typename TMap::const_iterator it_;
    };

    static_assert(std::bidirectional_iterator<Iterator>);

    explicit MapValuesView(const TMap& map)
        : begin_(Iterator{map.cbegin()}),
          end_(Iterator{map.cend()}) {}
    MapValuesView() = default;

    Iterator begin() const { return begin_; }
    Iterator end() const { return end_; }

  private:
    Iterator begin_;
    Iterator end_;
};

}  // namespace silkworm::map_values_view::fallback

namespace silkworm::map_values_view::builtin {

template <typename TMapKey, typename TMapValue, class TMap>
using MapValuesView = std::ranges::values_view<std::ranges::views::all_t<const TMap&>>;

}  // namespace silkworm::map_values_view::builtin

namespace silkworm {

// std::views::values is not present on clang 15
#if defined(__clang__) && (__clang_major__ <= 15) && !defined(__apple_build_version__)
using silkworm::map_values_view::fallback::MapValuesView;
#elif defined(__clang__) && (__clang_major__ <= 14) && defined(__apple_build_version__)  // clang 15 == Apple clang 14
using silkworm::map_values_view::fallback::MapValuesView;
#else
using silkworm::map_values_view::builtin::MapValuesView;
#endif

template <typename TMapKey, typename TMapValue>
MapValuesView<TMapKey, TMapValue, std::map<TMapKey, TMapValue>> make_map_values_view(const std::map<TMapKey, TMapValue>& map) {
    return MapValuesView<TMapKey, TMapValue, std::map<TMapKey, TMapValue>>{map};
}

template <typename TMapKey, typename TMapValue>
MapValuesView<TMapKey, TMapValue, std::unordered_map<TMapKey, TMapValue>> make_map_values_view(const std::unordered_map<TMapKey, TMapValue>& map) {
    return MapValuesView<TMapKey, TMapValue, std::unordered_map<TMapKey, TMapValue>>{map};
}

template <typename TMapKey, typename TMapValue, class THash>
MapValuesView<TMapKey, TMapValue, absl::flat_hash_map<TMapKey, TMapValue, THash>> make_map_values_view(const absl::flat_hash_map<TMapKey, TMapValue, THash>& map) {
    return MapValuesView<TMapKey, TMapValue, absl::flat_hash_map<TMapKey, TMapValue, THash>>{map};
}

template <typename TMapKey, typename TMapValue, class TMap>
using MapValuesViewReverse = std::ranges::reverse_view<MapValuesView<TMapKey, TMapValue, TMap>>;

}  // namespace silkworm
