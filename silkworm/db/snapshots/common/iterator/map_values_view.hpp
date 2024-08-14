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

#include <iterator>
#include <map>
#include <ranges>
#include <utility>

namespace silkworm {

template <typename TMapKey, typename TMapValue>
class MapValuesView : std::ranges::view_interface<MapValuesView<TMapKey, TMapValue>> {
  public:
    using Map = std::map<TMapKey, TMapValue>;

    class Iterator {
      public:
        using value_type = typename Map::mapped_type;
        using iterator_category [[maybe_unused]] = std::bidirectional_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using reference = const value_type&;

        Iterator(typename Map::const_iterator it) : it_(it) {}
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
        typename Map::const_iterator it_;
    };

    static_assert(std::bidirectional_iterator<Iterator>);

    MapValuesView(const Map& map)
        : begin_(Iterator{map.cbegin()}),
          end_(Iterator{map.cend()}) {}
    MapValuesView() = default;

    Iterator begin() const { return begin_; }
    Iterator end() const { return end_; }

  private:
    Iterator begin_;
    Iterator end_;
};

template <typename TMapKey, typename TMapValue>
auto make_map_values_view(const std::map<TMapKey, TMapValue>& map) {
    // std::views::values is not present on clang 15
#if defined(__clang__) && (__clang_major__ <= 15) && !defined(__apple_build_version__)
    return MapValuesView<TMapKey, TMapValue>{map};
#elif defined(__clang__) && (__clang_major__ <= 14) && defined(__apple_build_version__)  // clang 15 == Apple clang 14
    return MapValuesView<TMapKey, TMapValue>{map};
#else
    return std::views::values(map);
#endif
}

}  // namespace silkworm
