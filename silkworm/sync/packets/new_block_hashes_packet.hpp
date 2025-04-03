// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/sync/internals/types.hpp>

namespace silkworm {

struct NewBlockHash {       // one particular block being announced
    Hash hash;              // hash of the block
    BlockNum block_num{0};  // number of the block
};

using NewBlockHashesPacket = std::vector<NewBlockHash>;

namespace rlp {

    void encode(Bytes& to, const NewBlockHash& from) noexcept;

    size_t length(const NewBlockHash& from) noexcept;

    DecodingResult decode(ByteView& from, NewBlockHash& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace rlp

inline std::string new_block_hashes_packet_to_string(const NewBlockHashesPacket& packet) {
    std::stringstream os;
    if (packet.size() == 1)
        os << "block num " << packet[0].block_num /* << " hash " << to_hex(packet[0].hash) */;
    else
        os << packet.size() << " new block hashes/nums";
    return os.str();
}

inline std::ostream& operator<<(std::ostream& os, const NewBlockHashesPacket& packet) {
    os << new_block_hashes_packet_to_string(packet);
    return os;
}

}  // namespace silkworm
