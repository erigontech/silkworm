// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <type_traits>

#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/sync/internals/types.hpp>

namespace silkworm::rlp {

/*
 * This concepts recognizes an eth66 packet and enable us to write generic encode/decode functions but require a c++20
 * compiler
 *
 * template <class T>
 * concept Eth66Packet = requires(T p) {
 *     p.request_id;
 *     p.request;
 * };
 *
 * So we can write generic functions like:
 *
 * template <Eth66Packet T>
 * inline void encode(Bytes& to, const T& from) noexcept { ... }
 */

template <typename T>
inline void encode_eth66_packet(Bytes& to, const T& from) noexcept {
    rlp::Header rlp_head{true, 0};

    rlp_head.payload_length += rlp::length(from.request_id);
    rlp_head.payload_length += rlp::length(from.request);

    rlp::encode_header(to, rlp_head);

    rlp::encode(to, from.request_id);
    rlp::encode(to, from.request);
}

template <typename T>
inline size_t length_eth66_packet(const T& from) noexcept {
    rlp::Header rlp_head{true, 0};

    rlp_head.payload_length += rlp::length(from.request_id);
    rlp_head.payload_length += rlp::length(from.request);

    size_t rlp_head_len = rlp::length_of_length(rlp_head.payload_length);

    return rlp_head_len + rlp_head.payload_length;
}

template <typename T>
inline DecodingResult decode_eth66_packet(ByteView& from, T& to, Leftover mode = Leftover::kProhibit) noexcept {
    return decode(from, mode, to.request_id, to.request);
}

}  // namespace silkworm::rlp
