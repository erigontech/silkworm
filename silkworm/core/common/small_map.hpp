/*
   Copyright 2023 The Silkworm Authors

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

#include <algorithm>
#include <array>
#include <concepts>
#include <initializer_list>
#include <iterator>
#include <map>
#include <utility>

#include <silkworm/core/common/assert.hpp>

namespace silkworm {

// SmallMap is a constexpr-friendly immutable map suitable for a small number of elements.
template <std::totally_ordered Key, std::default_initializable T, std::size_t MaxSize = 8>
class SmallMap {
  public:
    using ValueType = std::pair<Key, T>;

    constexpr SmallMap() noexcept = default;

    constexpr SmallMap(std::initializer_list<ValueType> init) : size_(init.size()) {
        SILKWORM_ASSERT(size_ <= MaxSize);
        for (size_t i{0}; i < size_; ++i) {
            data_[i] = *(std::data(init) + i);
        }
        sort();
    }

    template <std::input_iterator InputIt>
    constexpr SmallMap(InputIt first, InputIt last) {
        for (InputIt it{first}; it != last; ++it) {
            SILKWORM_ASSERT(size_ < MaxSize);
            data_[size_++] = *it;
        }
        sort();
    }

    constexpr SmallMap(const SmallMap& other) {
        size_ = other.size_;
        for (size_t i{0}; i < MaxSize; ++i) {
            data_[i] = other.data_[i];
        }
    }
    constexpr SmallMap& operator=(const SmallMap& other) {
        size_ = other.size_;
        for (size_t i{0}; i < MaxSize; ++i) {
            data_[i] = other.data_[i];
        }
        return *this;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size_ == 0;
    }

    [[nodiscard]] constexpr std::size_t size() const noexcept {
        return size_;
    }

    [[nodiscard]] constexpr auto begin() const noexcept {
        return data_.begin();
    }

    [[nodiscard]] constexpr auto end() const noexcept {
        return begin() + size_;
    }

    [[nodiscard]] constexpr const T* find(const Key& key) const noexcept {
        // linear search is faster than binary for small sizes
        for (size_t i{0}; i < size_; ++i) {
            if (data_[i].first == key) {
                return &data_[i].second;
            }
        }
        return nullptr;
    }

    template <std::constructible_from<Key> NewKeyType = Key>
    [[nodiscard]] std::map<NewKeyType, T> to_std_map() const {
        std::map<NewKeyType, T> ret;
        for (const auto& [key, val] : *this) {
            ret[NewKeyType(key)] = val;
        }
        return ret;
    }

  private:
    constexpr void sort() {
        std::sort(data_.begin(), data_.begin() + size_,
                  [](const ValueType& a, const ValueType& b) { return a.first < b.first; });
    }

    std::array<ValueType, MaxSize> data_{};
    std::size_t size_{0};
};

template <std::totally_ordered Key, std::equality_comparable T>
constexpr bool operator==(const SmallMap<Key, T>& a, const SmallMap<Key, T>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

}  // namespace silkworm
