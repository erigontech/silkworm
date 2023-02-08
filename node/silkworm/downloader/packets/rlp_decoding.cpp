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

// types
#include <silkworm/downloader/internals/types.hpp>

#include "block_bodies_packet.hpp"
#include "block_headers_packet.hpp"
#include "get_block_bodies_packet.hpp"
#include "get_block_headers_packet.hpp"
#include "new_block_hashes_packet.hpp"
#include "new_block_packet.hpp"

// generic implementations (must follow types)
#include <silkworm/rlp/decode.hpp>

#include "rlp_eth66_packet_coding.hpp"

// specific implementations
namespace silkworm::rlp {

template <>
DecodingResult decode(ByteView& from, Hash& to) noexcept {
    return rlp::decode(from, static_cast<evmc::bytes32&>(to));
}

template <>
DecodingResult decode(ByteView& from, NewBlockHash& to) noexcept {
    const auto rlp_head{decode_header(from)};
    if (!rlp_head) {
        return tl::unexpected{rlp_head.error()};
    }
    if (!rlp_head->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    uint64_t leftover{from.length() - rlp_head->payload_length};

    if (DecodingResult res{rlp::decode(from, to.hash)}; !res) {
        return res;
    }
    if (DecodingResult res{rlp::decode(from, to.number)}; !res) {
        return res;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kListLengthMismatch};
    }
    return {};
}

template <>
DecodingResult decode(ByteView& from, NewBlockPacket& to) noexcept {
    const auto rlp_head{decode_header(from)};
    if (!rlp_head) {
        return tl::unexpected{rlp_head.error()};
    }
    if (!rlp_head->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    uint64_t leftover{from.length() - rlp_head->payload_length};

    if (DecodingResult res{rlp::decode(from, to.block)}; !res) {
        return res;
    }
    if (DecodingResult res{rlp::decode(from, to.td)}; !res) {
        return res;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kListLengthMismatch};
    }
    return {};
}

template <>
DecodingResult decode(ByteView& from, GetBlockHeadersPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, BlockBodiesPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, BlockHeadersPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, GetBlockBodiesPacket66& to) noexcept {
    return rlp::decode_eth66_packet(from, to);
}

template <>
DecodingResult decode(ByteView& from, GetBlockHeadersPacket& to) noexcept {
    const auto rlp_head{decode_header(from)};
    if (!rlp_head) {
        return tl::unexpected{rlp_head.error()};
    }
    if (!rlp_head->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }

    uint64_t leftover{from.length() - rlp_head->payload_length};

    if (DecodingResult res{rlp::decode(from, to.origin)}; !res) {
        return res;
    }
    if (DecodingResult res{rlp::decode(from, to.amount)}; !res) {
        return res;
    }
    if (DecodingResult res{rlp::decode(from, to.skip)}; !res) {
        return res;
    }
    if (DecodingResult res{rlp::decode(from, to.reverse)}; !res) {
        return res;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kListLengthMismatch};
    }
    return {};
}

}  // namespace silkworm::rlp
