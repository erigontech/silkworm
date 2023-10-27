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
#include <initializer_list>
#include <iterator>
#include <utility>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>

namespace silkworm {

// ConfigMap is a càdlàg map of starting_from_block -> value.
// For example, ConfigMap<std::string>{{0, "a"}, {10, "b"}, {20, "c"}}
// means that the config value is "a" for blocks 0–9,
// "b" for blocks 10–19, and "c" for block 20 and above.
// N.B. This class is constexpr-friendly.
template <typename T>
class ConfigMap {
  public:
    using ValueType = std::pair<BlockNum, T>;

    static constexpr std::size_t kMaxSize{8};

    constexpr ConfigMap() noexcept = default;

    constexpr ConfigMap(std::initializer_list<ValueType> init) : size_(init.size()) {
        SILKWORM_ASSERT(size_ <= kMaxSize);
        for (size_t i{0}; i < size_; ++i) {
            data_[i] = *(std::data(init) + i);
        }
        sort();
    }

    template <std::input_iterator InputIt>
    constexpr ConfigMap(InputIt first, InputIt last) {
        for (InputIt it{first}; it != last; ++it) {
            SILKWORM_ASSERT(size_ < kMaxSize);
            data_[size_++] = *it;
        }
        sort();
    }

    constexpr ConfigMap(const ConfigMap& other) = default;
    constexpr ConfigMap& operator=(const ConfigMap& other) = default;

    constexpr bool operator==(const ConfigMap&) const = default;

    // Looks up a config value as of a given block number.
    // Similar to borKeyValueConfigHelper in Erigon.
    [[nodiscard]] constexpr const T* value(BlockNum number) const noexcept {
        if (empty() || data_[0].first > number) {
            return nullptr;
        }
        for (size_t i{0}; i < size_ - 1; ++i) {
            if (data_[i].first <= number && number < data_[i + 1].first) {
                return &data_[i].second;
            }
        }
        return &data_[size_ - 1].second;
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return size_ == 0;
    }

    [[nodiscard]] constexpr const ValueType* begin() const noexcept {
        return data_.begin();
    }

    [[nodiscard]] constexpr const ValueType* end() const noexcept {
        return begin() + size_;
    }

  private:
    constexpr void sort() {
        std::sort(data_.begin(), data_.begin() + size_,
                  [](const ValueType& a, const ValueType& b) { return a.first < b.first; });
    }

    std::array<ValueType, kMaxSize> data_{};
    std::size_t size_{0};
};

}  // namespace silkworm
