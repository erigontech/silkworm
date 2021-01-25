/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_RLP_DECODE_H_
#define SILKWORM_RLP_DECODE_H_

#include <array>
#include <cstring>
#include <gsl/span>
#include <intx/intx.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/rlp/encode.hpp>
#include <utility>
#include <vector>

namespace silkworm::rlp {

enum class DecodingError {
    kOk = 0,
    kOverflow,
    kLeadingZero,
    kInputTooShort,
    kNonCanonicalSingleByte,
    kNonCanonicalSize,
    kUnexpectedLength,
    kUnexpectedString,
    kUnexpectedList,
    kInputListHasTooManyElements,
};

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
std::pair<Header, DecodingError> decode_header(ByteView& from) noexcept;

template <class T>
[[nodiscard]] DecodingError decode(ByteView& from, T& to) noexcept;

template <>
[[nodiscard]] DecodingError decode(ByteView& from, Bytes& to) noexcept;

template <>
[[nodiscard]] DecodingError decode(ByteView& from, uint64_t& to) noexcept;

template <>
[[nodiscard]] DecodingError decode(ByteView& from, intx::uint256& to) noexcept;

template <size_t N>
[[nodiscard]] DecodingError decode(ByteView& from, gsl::span<uint8_t, N> to) noexcept {
    static_assert(N != gsl::dynamic_extent);

    auto [h, err]{decode_header(from)};
    if (err != DecodingError::kOk) {
        return err;
    }
    if (h.list) {
        return DecodingError::kUnexpectedList;
    }
    if (h.payload_length != N) {
        return DecodingError::kUnexpectedLength;
    }

    std::memcpy(to.data(), from.data(), N);
    from.remove_prefix(N);
    return DecodingError::kOk;
}

template <size_t N>
[[nodiscard]] DecodingError decode(ByteView& from, uint8_t (&to)[N]) noexcept {
    return decode<N>(from, gsl::span<uint8_t, N>{to});
}

template <size_t N>
[[nodiscard]] DecodingError decode(ByteView& from, std::array<uint8_t, N>& to) noexcept {
    return decode<N>(from, gsl::span<uint8_t, N>{to});
}

template <class T>
[[nodiscard]] DecodingError decode_vector(ByteView& from, std::vector<T>& to) noexcept {
    auto [h, err]{decode_header(from)};
    if (err != DecodingError::kOk) {
        return err;
    }
    if (!h.list) {
        return DecodingError::kUnexpectedString;
    }

    to.clear();

    ByteView payload_view{from.substr(0, h.payload_length)};
    while (!payload_view.empty()) {
        to.emplace_back();
        if (DecodingError err{decode(payload_view, to.back())}; err != DecodingError::kOk) {
            return err;
        }
    }

    from.remove_prefix(h.payload_length);
    return DecodingError::kOk;
}

std::pair<uint64_t, DecodingError> read_uint64(ByteView big_endian, bool allow_leading_zeros = false) noexcept;

std::pair<intx::uint256, DecodingError> read_uint256(ByteView big_endian, bool allow_leading_zeros = false) noexcept;

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_DECODE_H_
