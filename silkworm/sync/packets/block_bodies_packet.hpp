// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

using BlockBodiesPacket = std::vector<BlockBody>;

struct BlockBodiesPacket66 {  // eth/66 version
    uint64_t request_id{0};
    BlockBodiesPacket request;
};

namespace rlp {

    size_t length(const BlockBodiesPacket66& from) noexcept;

    void encode(Bytes& to, const BlockBodiesPacket66& from);

    DecodingResult decode(ByteView& from, BlockBodiesPacket66& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockBodiesPacket66& packet) {
    os << "reqId=" << packet.request_id;
    os << " bodies=" << packet.request.size();
    return os;
}

}  // namespace silkworm
