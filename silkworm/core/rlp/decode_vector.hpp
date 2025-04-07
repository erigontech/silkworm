// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm::rlp {

//! Decodes an RLP list of dynamic size with items of type T
template <typename T>
DecodingResult decode(ByteView& from, std::vector<T>& to, Leftover mode = Leftover::kProhibit) noexcept {
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
        if (DecodingResult res{decode(payload_view, to.back(), Leftover::kAllow)}; !res) {
            return res;
        }
    }

    from.remove_prefix(h->payload_length);
    if (mode != Leftover::kAllow && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

template <typename Arg1, typename Arg2>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2) noexcept {
    if (DecodingResult res{decode(from, arg1, Leftover::kAllow)}; !res) {
        return res;
    }
    return decode(from, arg2, Leftover::kAllow);
}

template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode_items(ByteView& from, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    if (DecodingResult res{decode(from, arg1, Leftover::kAllow)}; !res) {
        return res;
    }
    return decode_items(from, arg2, args...);
}

//! Decodes an RLP list with a fixed number of items with various types
template <typename Arg1, typename Arg2, typename... Args>
DecodingResult decode(ByteView& from, Leftover mode, Arg1& arg1, Arg2& arg2, Args&... args) noexcept {
    const auto header{decode_header(from)};
    if (!header) {
        return tl::unexpected{header.error()};
    }
    if (!header->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }
    const uint64_t leftover{from.size() - header->payload_length};
    if (mode != Leftover::kAllow && leftover) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }

    if (DecodingResult res{decode_items(from, arg1, arg2, args...)}; !res) {
        return res;
    }

    if (from.size() != leftover) {
        return tl::unexpected{DecodingError::kUnexpectedListElements};
    }
    return {};
}

/**
 * Decodes an RLP list of dynamic size with items of any type.
 * The resulting RlpByteView-s refer to RLP-encoded data of the list items.
 * Use rlp::decode(to[i].data, ...) to fully decode them.
 */
template <>
inline DecodingResult decode(ByteView& from, std::vector<RlpByteView>& to, Leftover mode) noexcept {
    auto header = decode_header(from);
    if (!header) {
        return tl::unexpected{header.error()};
    }
    if (!header->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    to.clear();

    ByteView payload_view = from.substr(0, header->payload_length);
    while (!payload_view.empty()) {
        auto item_start = payload_view.begin();
        auto item_header = decode_header(payload_view);
        if (!item_header) {
            return tl::unexpected{header.error()};
        }
        auto item_end = payload_view.begin() + item_header->payload_length;
        to.emplace_back(ByteView{std::span{item_start, item_end}});
        payload_view.remove_prefix(item_header->payload_length);
    }

    from.remove_prefix(header->payload_length);
    if ((mode != Leftover::kAllow) && !from.empty()) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

}  // namespace silkworm::rlp
