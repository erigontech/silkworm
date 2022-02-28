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

    template <>
    DecodingResult decode(ByteView& from, BlockBodiesPacket& to) noexcept;

    size_t length(const BlockBodiesPacket66& from) noexcept;

    void encode(Bytes& to, const BlockBodiesPacket66& from);

    template <>
    DecodingResult decode(ByteView& from, BlockBodiesPacket66& to) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockBodiesPacket66& packet) {
    os << "reqId=" << packet.requestId;
    os << " bodies=" << packet.request.size();
    return os;
}

}  // namespace silkworm

#endif  // SILKWORM_BLOCKBODIESPACKET_HPP
