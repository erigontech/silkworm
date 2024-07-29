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

#include <cstdint>
#include <span>

#include <evmc/bytes.hpp>

namespace silkworm {

using Bytes = evmc::bytes;

class ByteView : public evmc::bytes_view {
  public:
    constexpr ByteView() noexcept = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const evmc::bytes_view& other) noexcept
        : evmc::bytes_view{other.data(), other.length()} {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    ByteView(const Bytes& str) noexcept : evmc::bytes_view{str.data(), str.length()} {}

    constexpr ByteView(const uint8_t* data, size_type length) noexcept
        : evmc::bytes_view{data, length} {}

    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const uint8_t (&array)[N]) noexcept : evmc::bytes_view{array, N} {}

    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const std::array<uint8_t, N>& array) noexcept
        : evmc::bytes_view{array.data(), N} {}

    template <std::size_t Extent>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(std::span<const uint8_t, Extent> span) noexcept
        : evmc::bytes_view{span.data(), span.size()} {}

    [[nodiscard]] bool is_null() const noexcept { return data() == nullptr; }
};

template <std::size_t Extent>
using ByteSpan = std::span<uint8_t, Extent>;

}  // namespace silkworm
