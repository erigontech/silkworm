/*
   Copyright 2022 The Silkworm Authors

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

// RLP decoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#pragma once

#include <array>
#include <cstring>
#include <span>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/rlp/encode.hpp>

namespace silkworm::rlp {

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
[[nodiscard]] tl::expected<Header, DecodingError> decode_header(ByteView& from) noexcept;

template <class T>
DecodingResult decode(ByteView& from, T& to) noexcept;

template <>
DecodingResult decode(ByteView& from, evmc::bytes32& to) noexcept;

template <>
DecodingResult decode(ByteView& from, Bytes& to) noexcept;

template <UnsignedIntegral T>
DecodingResult decode(ByteView& from, T& to) noexcept {
    const auto h{decode_header(from)};
    if (!h) {
        return tl::unexpected{h.error()};
    }
    if (h->list) {
        return tl::unexpected{DecodingError::kUnexpectedList};
    }
    if (DecodingResult res{endian::from_big_compact(from.substr(0, h->payload_length), to)}; !res) {
        return tl::unexpected{res.error()};
    }
    from.remove_prefix(h->payload_length);
    return {};
}

template <>
DecodingResult decode(ByteView& from, bool& to) noexcept;

template <size_t N>
DecodingResult decode(ByteView& from, std::span<uint8_t, N> to) noexcept {
    static_assert(N != std::dynamic_extent);

    const auto h{decode_header(from)};
    if (!h) {
        return tl::unexpected{h.error()};
    }
    if (h->list) {
        return tl::unexpected{DecodingError::kUnexpectedList};
    }
    if (h->payload_length != N) {
        return tl::unexpected{DecodingError::kUnexpectedLength};
    }

    std::memcpy(to.data(), from.data(), N);
    from.remove_prefix(N);
    return {};
}

template <size_t N>
DecodingResult decode(ByteView& from, uint8_t (&to)[N]) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to});
}

template <size_t N>
DecodingResult decode(ByteView& from, std::array<uint8_t, N>& to) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to});
}

template <class T>
DecodingResult decode(ByteView& from, std::vector<T>& to) noexcept {
    const auto h{decode_header(from)};
    if (!h) {
        return tl::unexpected{h.error()};
    }
    if (!h->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    to.clear();

    ByteView payload_view{from.substr(0, h->payload_length)};
    while (!payload_view.empty()) {
        to.emplace_back();
        if (DecodingResult res{decode(payload_view, to.back())}; !res) {
            return tl::unexpected{res.error()};
        }
    }

    from.remove_prefix(h->payload_length);
    return {};
}

template <typename Arg1, typename Arg2>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2) noexcept {
    if (DecodingResult res{decode(from, arg1)}; !res) {
        return tl::unexpected{res.error()};
    }
    return decode(from, arg2);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    if (DecodingResult res{decode(from, arg1)}; !res) {
        return tl::unexpected{res.error()};
    }
    return decode_items(from, arg2, args...);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    const auto header{decode_header(from)};
    if (!header) {
        return tl::unexpected{header.error()};
    }
    if (!header->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }
    return decode_items(from, arg1, arg2, args...);
}

}  // namespace silkworm::rlp
