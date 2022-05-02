/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_RLPETH66PACKETS_HPP
#define SILKWORM_RLPETH66PACKETS_HPP

#include <type_traits>

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm::rlp {

/*
 * This concepts recognizes an eth66 packet and enable us to write generic encode/decode functions but require a c++20
 * compiler
 *
 * template <class T>
 * concept Eth66Packet = requires(T p) {
 *     p.requestId;
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

    rlp_head.payload_length += rlp::length(from.requestId);
    rlp_head.payload_length += rlp::length(from.request);

    rlp::encode_header(to, rlp_head);

    rlp::encode(to, from.requestId);
    rlp::encode(to, from.request);
}

template <typename T>
inline size_t length_eth66_packet(const T& from) noexcept {
    rlp::Header rlp_head{true, 0};

    rlp_head.payload_length += rlp::length(from.requestId);
    rlp_head.payload_length += rlp::length(from.request);

    size_t rlp_head_len = rlp::length_of_length(rlp_head.payload_length);

    return rlp_head_len + rlp_head.payload_length;
}

template <typename T>
inline DecodingResult decode_eth66_packet(ByteView& from, T& to) noexcept {
    auto [rlp_head, err0]{rlp::decode_header(from)};
    if (err0 != DecodingResult::kOk) {
        return err0;
    }
    if (!rlp_head.list) {
        return DecodingResult::kUnexpectedString;
    }

    uint64_t leftover{from.length() - rlp_head.payload_length};

    if (DecodingResult err{rlp::decode(from, to.requestId)}; err != DecodingResult::kOk) {
        return err;
    }
    if (DecodingResult err{rlp::decode(from, to.request)}; err != DecodingResult::kOk) {
        return err;
    }

    return from.length() == leftover ? DecodingResult::kOk : DecodingResult::kListLengthMismatch;
}

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLPETH66PACKETS_HPP
