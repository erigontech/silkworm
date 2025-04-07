// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

using BlockHeadersPacket = std::vector<BlockHeader>;

struct BlockHeadersPacket66 {  // eth/66 version
    uint64_t request_id{0};
    BlockHeadersPacket request;

    std::string to_string() const;
};

namespace rlp {

    size_t length(const BlockHeadersPacket66& from) noexcept;

    void encode(Bytes& to, const BlockHeadersPacket66& from);

    DecodingResult decode(ByteView& from, BlockHeadersPacket66& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const BlockHeadersPacket66& packet) {
    os << packet.to_string();
    return os;
}

inline std::string BlockHeadersPacket66::to_string() const {
    const auto& packet = *this;
    std::stringstream os;

    os << "reqId=" << packet.request_id;
    os << " headers(block_num)=";

    const size_t max_display = 3;
    for (size_t i = 0; i < std::min(packet.request.size(), max_display); ++i) {
        os << packet.request[i].number << ",";
    }
    if (packet.request.size() > max_display) os << "...";

    return os.str();
}

}  // namespace silkworm
