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
