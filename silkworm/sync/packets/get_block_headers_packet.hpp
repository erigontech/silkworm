// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "hash_or_number.hpp"

namespace silkworm {

struct GetBlockHeadersPacket {
    HashOrNumber origin;  // Block hash or block number from which to retrieve headers
    uint64_t amount{0};   // Maximum number of headers to retrieve
    uint64_t skip{0};     // Blocks to skip between consecutive headers
    bool reverse{false};  // Query direction (false = rising towards latest, true = falling towards genesis)
};

struct GetBlockHeadersPacket66 {  // eth/66 version
    uint64_t request_id{0};
    GetBlockHeadersPacket request;
};

namespace rlp {

    void encode(Bytes& to, const GetBlockHeadersPacket& from) noexcept;

    size_t length(const GetBlockHeadersPacket& from) noexcept;

    DecodingResult decode(ByteView& from, GetBlockHeadersPacket& to, Leftover mode = Leftover::kProhibit) noexcept;

    size_t length(const GetBlockHeadersPacket66& from) noexcept;

    void encode(Bytes& to, const GetBlockHeadersPacket66& from) noexcept;

    DecodingResult decode(ByteView& from, GetBlockHeadersPacket66& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const GetBlockHeadersPacket66& packet) {
    os << "reqId=" << packet.request_id << " origin=" << packet.request.origin << " amount=" << packet.request.amount
       << " skip=" << packet.request.skip << " reverse=" << packet.request.reverse;
    return os;
}

}  // namespace silkworm
