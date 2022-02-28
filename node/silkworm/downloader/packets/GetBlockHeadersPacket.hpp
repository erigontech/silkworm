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

#ifndef SILKWORM_GETBLOCKHEADERSPACKET_HPP
#define SILKWORM_GETBLOCKHEADERSPACKET_HPP

#include "HashOrNumber.hpp"

namespace silkworm {

struct GetBlockHeadersPacket {
    HashOrNumber origin;  // Block hash or block number from which to retrieve headers
    uint64_t amount;      // Maximum number of headers to retrieve
    uint64_t skip;        // Blocks to skip between consecutive headers
    bool reverse;         // Query direction (false = rising towards latest, true = falling towards genesis)
};

struct GetBlockHeadersPacket66 {  // eth/66 version
    uint64_t requestId;
    GetBlockHeadersPacket request;
};

namespace rlp {

    void encode(Bytes& to, const GetBlockHeadersPacket& from) noexcept;

    size_t length(const GetBlockHeadersPacket& from) noexcept;

    template <>
    DecodingResult decode(ByteView& from, GetBlockHeadersPacket& to) noexcept;

    size_t length(const GetBlockHeadersPacket66& from) noexcept;

    void encode(Bytes& to, const GetBlockHeadersPacket66& from) noexcept;

    template <>
    DecodingResult decode(ByteView& from, GetBlockHeadersPacket66& to) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const GetBlockHeadersPacket66& packet) {
    os << "reqId=" << packet.requestId << " origin=" << packet.request.origin << " amount=" << packet.request.amount
       << " skip=" << packet.request.skip << " reverse=" << packet.request.reverse;
    return os;
}

}  // namespace silkworm

#endif  // SILKWORM_GETBLOCKHEADERSPACKET_HPP
