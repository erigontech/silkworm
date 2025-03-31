// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

struct NewBlockPacket {
    Block block;
    BigInt td;  // total difficulty
};

namespace rlp {

    void encode(Bytes& to, const NewBlockPacket& from) noexcept;

    size_t length(const NewBlockPacket& from) noexcept;

    DecodingResult decode(ByteView& from, NewBlockPacket& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::ostream& operator<<(std::ostream& os, const NewBlockPacket& packet) {
    os << "block num " << packet.block.header.number;
    return os;
}

}  // namespace silkworm
