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

#ifndef SILKWORM_NEWBLOCKHASHPACKET_HPP
#define SILKWORM_NEWBLOCKHASHPACKET_HPP

#include <silkworm/downloader/internals/types.hpp>

namespace silkworm {

struct NewBlockHash {    // one particular block being announced
    Hash hash;           // hash of the block
    BlockNum number{0};  // number of the block
};

using NewBlockHashesPacket = std::vector<NewBlockHash>;

namespace rlp {

    void encode(Bytes& to, const NewBlockHash& from) noexcept;

    size_t length(const NewBlockHash& from) noexcept;

    template <>
    DecodingResult decode(ByteView& from, NewBlockHash& to) noexcept;

    template <>
    DecodingResult decode(ByteView& from, NewBlockHashesPacket& to) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const NewBlockHashesPacket& packet) {
    if (packet.size() == 1)
        os << "block num " << packet[0].number /* << " hash " << to_hex(packet[0].hash) */;
    else
        os << packet.size() << " new block hashes/nums";
    return os;
}

}  // namespace silkworm

#endif  // SILKWORM_NEWBLOCKHASHPACKET_HPP
