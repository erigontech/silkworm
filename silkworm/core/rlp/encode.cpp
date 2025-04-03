// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "encode.hpp"

namespace silkworm::rlp {

void encode_header(Bytes& to, Header header) {
    if (header.payload_length < 56) {
        const uint8_t code{header.list ? kEmptyListCode : kEmptyStringCode};
        to.push_back(static_cast<uint8_t>(code + header.payload_length));
    } else {
        auto len_be{endian::to_big_compact(header.payload_length)};
        const uint8_t code = header.list ? 0xF7 : 0xB7;
        to.push_back(static_cast<uint8_t>(code + len_be.size()));
        to.append(len_be);
    }
}

size_t length_of_length(uint64_t payload_length) noexcept {
    if (payload_length < 56) {
        return 1;
    }
    return 1 + intx::count_significant_bytes(payload_length);
}

void encode(Bytes& to, bool x) {
    to.push_back(x ? uint8_t{1} : kEmptyStringCode);
}

void encode(Bytes& to, ByteView s) {
    if (s.size() != 1 || s[0] >= kEmptyStringCode) {
        encode_header(to, {.list = false, .payload_length = s.size()});
    }
    to.append(s);
}

size_t length(ByteView s) noexcept {
    size_t len{s.size()};
    if (s.size() != 1 || s[0] >= kEmptyStringCode) {
        len += length_of_length(s.size());
    }
    return len;
}

}  // namespace silkworm::rlp
