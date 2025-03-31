// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

// clang-format off
#include <silkworm/sync/internals/types.hpp>  // types
// clang-format on

#include <silkworm/core/rlp/encode_vector.hpp>  // generic implementations (must follow types)

#include "block_bodies_packet.hpp"
#include "block_headers_packet.hpp"
#include "get_block_bodies_packet.hpp"
#include "get_block_headers_packet.hpp"
#include "new_block_hashes_packet.hpp"
#include "new_block_packet.hpp"
#include "rlp_eth66_packet_coding.hpp"

namespace silkworm::rlp {

void encode(Bytes& to, const Hash& h) { rlp::encode(to, ByteView{h}); }

size_t length(const BlockBodiesPacket66& from) noexcept { return rlp::length_eth66_packet(from); }

void encode(Bytes& to, const BlockBodiesPacket66& from) { rlp::encode_eth66_packet(to, from); }

size_t length(const BlockHeadersPacket66& from) noexcept { return rlp::length_eth66_packet(from); }

void encode(Bytes& to, const BlockHeadersPacket66& from) { rlp::encode_eth66_packet(to, from); }

size_t length(const GetBlockBodiesPacket66& from) noexcept { return rlp::length_eth66_packet(from); }

void encode(Bytes& to, const GetBlockBodiesPacket66& from) { rlp::encode_eth66_packet(to, from); }

// NewBlockHash
size_t length(const NewBlockHash& from) noexcept {
    rlp::Header rlp_head{true, rlp::length(from.hash) + rlp::length(from.block_num)};

    size_t rlp_head_len = rlp::length_of_length(rlp_head.payload_length);
    return rlp_head_len + rlp_head.payload_length;
}

void encode(Bytes& to, const NewBlockHash& from) noexcept {
    rlp::Header rlp_head{true, rlp::length(from.hash) + rlp::length(from.block_num)};

    rlp::encode_header(to, rlp_head);

    rlp::encode(to, from.hash);
    rlp::encode(to, from.block_num);
}

// NewBlockPacket
void encode(Bytes& to, const NewBlockPacket& from) noexcept {
    rlp::Header rlp_head{true, rlp::length(from.block) + rlp::length(from.td)};

    rlp::encode_header(to, rlp_head);

    rlp::encode(to, from.block);
    rlp::encode(to, from.td);
}

size_t length(const NewBlockPacket& from) noexcept {
    rlp::Header rlp_head{true, rlp::length(from.block) + rlp::length(from.td)};

    size_t rlp_head_len = rlp::length_of_length(rlp_head.payload_length);
    return rlp_head_len + rlp_head.payload_length;
}

// GetBlockHeadersPacket
size_t length(const GetBlockHeadersPacket& from) noexcept {
    rlp::Header rlp_head{true, 0};

    rlp_head.payload_length += rlp::length(from.origin);
    rlp_head.payload_length += rlp::length(from.amount);
    rlp_head.payload_length += rlp::length(from.skip);
    rlp_head.payload_length += rlp::length(from.reverse);

    size_t rlp_head_len = rlp::length_of_length(rlp_head.payload_length);

    return rlp_head_len + rlp_head.payload_length;
}

void encode(Bytes& to, const GetBlockHeadersPacket& from) noexcept {
    rlp::Header rlp_head{true, 0};

    rlp_head.payload_length += rlp::length(from.origin);
    rlp_head.payload_length += rlp::length(from.amount);
    rlp_head.payload_length += rlp::length(from.skip);
    rlp_head.payload_length += rlp::length(from.reverse);

    rlp::encode_header(to, rlp_head);

    rlp::encode(to, from.origin);
    rlp::encode(to, from.amount);
    rlp::encode(to, from.skip);
    rlp::encode(to, from.reverse);
}

size_t length(const GetBlockHeadersPacket66& from) noexcept { return rlp::length_eth66_packet(from); }

void encode(Bytes& to, const GetBlockHeadersPacket66& from) noexcept { rlp::encode_eth66_packet(to, from); }

}  // namespace silkworm::rlp
