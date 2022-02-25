/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "decode.hpp"

#include <cassert>
#include <tuple>

#include <silkworm/common/endian.hpp>

namespace silkworm::rlp {

std::pair<Header, DecodingResult> decode_header(ByteView& from) noexcept {
    Header h;
    if (from.empty()) {
        return {h, DecodingResult::kInputTooShort};
    }

    uint8_t b{from[0]};
    if (b < 0x80) {
        h.payload_length = 1;
    } else if (b < 0xB8) {
        from.remove_prefix(1);
        h.payload_length = b - 0x80u;
        if (h.payload_length == 1) {
            if (from.empty()) {
                return {h, DecodingResult::kInputTooShort};
            }
            if (from[0] < 0x80) {
                return {h, DecodingResult::kNonCanonicalSize};
            }
        }
    } else if (b < 0xC0) {
        from.remove_prefix(1);
        const size_t len_of_len{b - 0xB7u};
        if (from.length() < len_of_len) {
            return {h, DecodingResult::kInputTooShort};
        }
        uint64_t len{0};
        DecodingResult err{endian::from_big_compact(from.substr(0, len_of_len), len)};
        if (err != DecodingResult::kOk) {
            return {h, err};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return {h, DecodingResult::kNonCanonicalSize};
        }
    } else if (b < 0xF8) {
        from.remove_prefix(1);
        h.list = true;
        h.payload_length = b - 0xC0u;
    } else {
        from.remove_prefix(1);
        h.list = true;
        const size_t len_of_len{b - 0xF7u};
        if (from.length() < len_of_len) {
            return {h, DecodingResult::kInputTooShort};
        }
        uint64_t len{0};
        DecodingResult err{endian::from_big_compact(from.substr(0, len_of_len), len)};
        if (err != DecodingResult::kOk) {
            return {h, err};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return {h, DecodingResult::kNonCanonicalSize};
        }
    }

    if (from.length() < h.payload_length) {
        return {h, DecodingResult::kInputTooShort};
    }

    return {h, DecodingResult::kOk};
}

template <>
DecodingResult decode(ByteView& from, evmc::bytes32& to) noexcept {
    return decode(from, to.bytes);
}

template <>
DecodingResult decode(ByteView& from, Bytes& to) noexcept {
    auto [h, err]{decode_header(from)};
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (h.list) {
        return DecodingResult::kUnexpectedList;
    }
    to = from.substr(0, h.payload_length);
    from.remove_prefix(h.payload_length);
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView& from, bool& to) noexcept {
    uint64_t i{0};
    if (DecodingResult err{decode(from, i)}; err != DecodingResult::kOk) {
        return err;
    }
    if (i > 1) {
        return DecodingResult::kOverflow;
    }
    to = i;
    return DecodingResult::kOk;
}

template <typename UnsignedInteger>
static DecodingResult decode_integer(ByteView& from, UnsignedInteger& to) noexcept {
    auto [h, err]{decode_header(from)};
    if (err != DecodingResult::kOk) {
        return err;
    }
    if (h.list) {
        return DecodingResult::kUnexpectedList;
    }
    err = endian::from_big_compact(from.substr(0, h.payload_length), to);
    if (err != DecodingResult::kOk) {
        return err;
    }
    from.remove_prefix(h.payload_length);
    return DecodingResult::kOk;
}

template <>
DecodingResult decode(ByteView& from, uint64_t& to) noexcept {
    return decode_integer<uint64_t>(from, to);
}

template <>
DecodingResult decode(ByteView& from, intx::uint256& to) noexcept {
    return decode_integer<intx::uint256>(from, to);
}
}  // namespace silkworm::rlp
