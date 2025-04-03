// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <span>
#include <variant>

#include <evmc/bytes.hpp>

namespace silkworm {

using Bytes = evmc::bytes;

class ByteView : public evmc::bytes_view {
  public:
    constexpr ByteView() noexcept = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const evmc::bytes_view& other) noexcept
        : evmc::bytes_view{other.data(), other.size()} {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    ByteView(const Bytes& str) noexcept : evmc::bytes_view{str.data(), str.size()} {}

    constexpr ByteView(const uint8_t* data, size_type size) noexcept
        : evmc::bytes_view{data, size} {}

    template <size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const uint8_t (&array)[N]) noexcept : evmc::bytes_view{array, N} {}

    template <size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const std::array<uint8_t, N>& array) noexcept
        : evmc::bytes_view{array.data(), N} {}

    template <size_t Extent>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(std::span<const uint8_t, Extent> span) noexcept
        : evmc::bytes_view{span.data(), span.size()} {}

    bool is_null() const noexcept { return data() == nullptr; }

  private:
    // see code style P28
    using evmc::bytes_view::length;
};

template <size_t Extent>
using ByteSpan = std::span<uint8_t, Extent>;

struct BytesOrByteView : public std::variant<Bytes, ByteView> {
    using std::variant<Bytes, ByteView>::operator=;

    bool holds_bytes() const { return std::holds_alternative<Bytes>(*this); }

    BytesOrByteView substr(size_t offset) {
        return holds_bytes() ? BytesOrByteView{std::get<Bytes>(*this).substr(offset)}
                             : BytesOrByteView{std::get<ByteView>(*this).substr(offset)};
    }

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    operator ByteView() const {
        return holds_bytes() ? std::get<Bytes>(*this) : std::get<ByteView>(*this);
    }
};

}  // namespace silkworm
