/*
   Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_BLOCKBODIESPACKET_HPP
#define SILKWORM_BLOCKBODIESPACKET_HPP

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

using BlockBodiesPacket = std::vector<BlockBody>;

struct BlockBodiesPacket66 {  // eth/66 version
    uint64_t requestId;
    BlockBodiesPacket request;
};

namespace rlp {

    // ... length(const BlockBodiesPacket& from)              impl. by length<T>(const std::vector<T>& v)

    // ... encode(Bytes& to, const BlockBodiesPacket& from)   impl. by encode(Bytes& to, const std::vector<T>& v)
    template <>
    rlp::DecodingResult decode(ByteView& from, BlockBodiesPacket& to) noexcept;

    // ... length(const BlockBodiesPacket66& from)            impl. by template <Eth66Packet T> size_t length(...)

    // ... encode(Bytes& to, const BlockBodiesPacket66& from) impl. by template <Eth66Packet T> void encode(...)

    // ... decode(ByteView& from, BlockBodiesPacket66& to) ->template<Eth66Packet T> auto decode(...) but requires c++20
    template <>
    rlp::DecodingResult decode(ByteView& from, BlockBodiesPacket66& to) noexcept;
}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockBodiesPacket66& packet) {
    os << "reqId=" << packet.requestId;
    os << " bodies=" << packet.request.size();
    return os;
}

}  // namespace silkworm

#include "RLPEth66PacketCoding.hpp"

#endif  // SILKWORM_BLOCKBODIESPACKET_HPP
