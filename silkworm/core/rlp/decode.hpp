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

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/rlp/encode.hpp>

namespace silkworm::rlp {

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
[[nodiscard]] tl::expected<Header, DecodingError> decode_header(ByteView& from) noexcept;

DecodingResult decode(ByteView& from, evmc::bytes32& to, bool allow_leftover = false) noexcept;

DecodingResult decode(ByteView& from, Bytes& to, bool allow_leftover = false) noexcept;

template <UnsignedIntegral T>
DecodingResult decode(ByteView& from, T& to, bool allow_leftover = false) noexcept {
    const auto h{decode_header(from)};
    if (!h) {
        return tl::unexpected{h.error()};
    }
    if (h->list) {
        return tl::unexpected{DecodingError::kUnexpectedList};
    }
    if (DecodingResult res{endian::from_big_compact(from.substr(0, h->payload_length), to)}; !res) {
        return res;
    }
    from.remove_prefix(h->payload_length);
    if (!allow_leftover && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

DecodingResult decode(ByteView& from, bool& to, bool allow_leftover = false) noexcept;

template <size_t N>
DecodingResult decode(ByteView& from, std::span<uint8_t, N> to, bool allow_leftover = false) noexcept {
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
    if (!allow_leftover && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

template <size_t N>
DecodingResult decode(ByteView& from, uint8_t (&to)[N], bool allow_leftover = false) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to}, allow_leftover);
}

template <size_t N>
DecodingResult decode(ByteView& from, std::array<uint8_t, N>& to, bool allow_leftover = false) noexcept {
    return decode<N>(from, std::span<uint8_t, N>{to}, allow_leftover);
}

}  // namespace silkworm::rlp
