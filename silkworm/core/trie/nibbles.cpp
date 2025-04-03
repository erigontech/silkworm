// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "nibbles.hpp"

namespace silkworm::trie {

Bytes pack_nibbles(ByteView unpacked) {
    if (unpacked.empty()) {
        return {};
    }

    size_t pos{unpacked.size() & 1};
    Bytes out((unpacked.size() + pos) / 2, '\0');
    auto out_it{out.begin()};
    while (unpacked.size() > pos) {
        *out_it++ = static_cast<uint8_t>((unpacked[0] << 4) + unpacked[1]);
        unpacked.remove_prefix(2);
    }
    if (pos) {
        *out_it = static_cast<uint8_t>(unpacked[0] << 4);
        unpacked.remove_prefix(1);
    }

    return out;
}

Bytes unpack_nibbles(ByteView data) {
    Bytes out(2 * data.size(), '\0');
    size_t offset{0};
    for (const auto& b : data) {
        out[offset] = b >> 4;
        out[offset + 1] = b & 0x0F;
        offset += 2;
    }
    return out;
}

}  // namespace silkworm::trie
