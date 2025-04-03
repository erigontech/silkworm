// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

using GetBlockBodiesPacket = std::vector<Hash>;

struct GetBlockBodiesPacket66 {  // eth/66 version
    uint64_t request_id{0};
    GetBlockBodiesPacket request;

    std::string to_string() const;
};

namespace rlp {

    size_t length(const GetBlockBodiesPacket66& from) noexcept;

    void encode(Bytes& to, const GetBlockBodiesPacket66& from);

    DecodingResult decode(ByteView& from, GetBlockBodiesPacket66& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const GetBlockBodiesPacket66& packet) {
    os << packet.to_string();
    return os;
}

inline std::string GetBlockBodiesPacket66::to_string() const {
    const auto& packet = *this;
    std::stringstream os;

    os << "reqId=" << packet.request_id;

    if (packet.request.size() == 1) {
        os << " hash=" << to_hex(packet.request[0]);
    } else {
        os << " requested=" << packet.request.size() << " block hashes";
    }
    return os.str();
}

}  // namespace silkworm
