// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

// types
#include <silkworm/sync/internals/types.hpp>

#include "block_bodies_packet.hpp"
#include "block_headers_packet.hpp"
#include "get_block_bodies_packet.hpp"
#include "get_block_headers_packet.hpp"
#include "new_block_hashes_packet.hpp"
#include "new_block_packet.hpp"
#include "rlp_eth66_packet_coding.hpp"

// specific implementations
namespace silkworm::rlp {

DecodingResult decode(ByteView& from, NewBlockHash& to, Leftover mode) noexcept {
    return decode(from, mode, to.hash, to.block_num);
}

DecodingResult decode(ByteView& from, NewBlockPacket& to, Leftover mode) noexcept {
    return decode(from, mode, to.block, to.td);
}

DecodingResult decode(ByteView& from, GetBlockHeadersPacket66& to, Leftover mode) noexcept {
    return rlp::decode_eth66_packet(from, to, mode);
}

DecodingResult decode(ByteView& from, BlockBodiesPacket66& to, Leftover mode) noexcept {
    return rlp::decode_eth66_packet(from, to, mode);
}

DecodingResult decode(ByteView& from, BlockHeadersPacket66& to, Leftover mode) noexcept {
    return rlp::decode_eth66_packet(from, to, mode);
}

DecodingResult decode(ByteView& from, GetBlockBodiesPacket66& to, Leftover mode) noexcept {
    return rlp::decode_eth66_packet(from, to, mode);
}

DecodingResult decode(ByteView& from, GetBlockHeadersPacket& to, Leftover mode) noexcept {
    return decode(from, mode, to.origin, to.amount, to.skip, to.reverse);
}

}  // namespace silkworm::rlp
