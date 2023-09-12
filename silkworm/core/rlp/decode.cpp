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

#include "decode.hpp"

#include <cassert>
#include <tuple>

#include <silkworm/core/common/endian.hpp>

namespace silkworm::rlp {

tl::expected<Header, DecodingError> decode_header(ByteView& from) noexcept {
    if (from.empty()) {
        return tl::unexpected{DecodingError::kInputTooShort};
    }

    Header h{.list = false};
    uint8_t b{from[0]};
    if (b < 0x80) {
        h.payload_length = 1;
    } else if (b < 0xB8) {
        from.remove_prefix(1);
        h.payload_length = b - 0x80u;
        if (h.payload_length == 1) {
            if (from.empty()) {
                return tl::unexpected{DecodingError::kInputTooShort};
            }
            if (from[0] < 0x80) {
                return tl::unexpected{DecodingError::kNonCanonicalSize};
            }
        }
    } else if (b < 0xC0) {
        from.remove_prefix(1);
        const size_t len_of_len{b - 0xB7u};
        if (from.length() < len_of_len) {
            return tl::unexpected{DecodingError::kInputTooShort};
        }
        uint64_t len{0};
        if (DecodingResult res{endian::from_big_compact(from.substr(0, len_of_len), len)}; !res) {
            return tl::unexpected{res.error()};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return tl::unexpected{DecodingError::kNonCanonicalSize};
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
            return tl::unexpected{DecodingError::kInputTooShort};
        }
        uint64_t len{0};
        if (DecodingResult res{endian::from_big_compact(from.substr(0, len_of_len), len)}; !res) {
            return tl::unexpected{res.error()};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return tl::unexpected{DecodingError::kNonCanonicalSize};
        }
    }

    if (from.length() < h.payload_length) {
        return tl::unexpected{DecodingError::kInputTooShort};
    }

    return h;
}

DecodingResult decode(ByteView& from, Bytes& to, Leftover mode) noexcept {
    const auto h{decode_header(from)};
    if (!h) {
        return tl::unexpected{h.error()};
    }
    if (h->list) {
        return tl::unexpected{DecodingError::kUnexpectedList};
    }
    to = from.substr(0, h->payload_length);
    from.remove_prefix(h->payload_length);
    if (mode != Leftover::kAllow && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

DecodingResult decode(ByteView& from, bool& to, Leftover mode) noexcept {
    uint64_t i{0};
    if (DecodingResult res{decode(from, i, mode)}; !res) {
        return tl::unexpected{res.error()};
    }
    if (i > 1) {
        return tl::unexpected{DecodingError::kOverflow};
    }
    to = i;
    return {};
}

}  // namespace silkworm::rlp
