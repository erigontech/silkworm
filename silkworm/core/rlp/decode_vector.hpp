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

#pragma once

#include <vector>

#include <silkworm/core/rlp/decode.hpp>

namespace silkworm::rlp {

template <typename T>
DecodingResult decode(ByteView& from, std::vector<T>& to, bool allow_leftover = false) noexcept {
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
        if (DecodingResult res{decode(payload_view, to.back(), /*allow_leftover=*/true)}; !res) {
            return res;
        }
    }

    from.remove_prefix(h->payload_length);
    if (!allow_leftover && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

template <typename Arg1, typename Arg2>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2) noexcept {
    if (DecodingResult res{decode(from, arg1, /*allow_leftover=*/true)}; !res) {
        return res;
    }
    return decode(from, arg2, /*allow_leftover=*/true);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    if (DecodingResult res{decode(from, arg1, /*allow_leftover=*/true)}; !res) {
        return res;
    }
    return decode_items(from, arg2, args...);
}

// Decodes an RLP list
template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode(ByteView& from, bool allow_leftover, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    const auto header{decode_header(from)};
    if (!header) {
        return tl::unexpected{header.error()};
    }
    if (!header->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }
    uint64_t leftover{from.length() - header->payload_length};

    if (DecodingResult res{decode_items(from, arg1, arg2, args...)}; !res) {
        return res;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    if (!allow_leftover && leftover) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

}  // namespace silkworm::rlp
