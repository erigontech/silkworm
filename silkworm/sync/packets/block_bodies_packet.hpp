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

#pragma once

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

using BlockBodiesPacket = std::vector<BlockBody>;

struct BlockBodiesPacket66 {  // eth/66 version
    uint64_t request_id{0};
    BlockBodiesPacket request;

    std::string to_string() const;
};

namespace rlp {

    size_t length(const BlockBodiesPacket66& from) noexcept;

    void encode(Bytes& to, const BlockBodiesPacket66& from);

    DecodingResult decode(ByteView& from, BlockBodiesPacket66& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockBodiesPacket66& packet) {
    os << packet.to_string();
    return os;
}

inline std::string BlockBodiesPacket66::to_string() const {
    const auto& packet = *this;
    std::stringstream os;

    os << "reqId=" << packet.request_id;
    os << " bodies=" << packet.request.size();
    return os.str();
}

}  // namespace silkworm
