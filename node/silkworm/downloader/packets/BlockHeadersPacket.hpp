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

#ifndef SILKWORM_BLOCKHEADERSPACKET_HPP
#define SILKWORM_BLOCKHEADERSPACKET_HPP

#include <algorithm>

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

using BlockHeadersPacket = std::vector<BlockHeader>;

struct BlockHeadersPacket66 {  // eth/66 version
    uint64_t requestId;
    BlockHeadersPacket request;
};

namespace rlp {

    template <>
    DecodingResult decode(ByteView& from, BlockHeadersPacket& to) noexcept;

    size_t length(const BlockHeadersPacket66& from) noexcept;

    void encode(Bytes& to, const BlockHeadersPacket66& from);

    template <>
    DecodingResult decode(ByteView& from, BlockHeadersPacket66& to) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockHeadersPacket66& packet) {
    os << "reqId=" << packet.requestId;
    os << " headers(bn)=";

    const size_t max_display = 3;
    for (size_t i = 0; i < std::min(packet.request.size(), max_display); i++) {
        os << packet.request[i].number << ",";
    }
    if (packet.request.size() > max_display) os << "...";

    return os;
}

}  // namespace silkworm

#endif  // SILKWORM_BLOCKHEADERSPACKET_HPP
