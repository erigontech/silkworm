// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

// RLP encoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#pragma once

#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/endian.hpp>

namespace silkworm::rlp {

struct Header {
    bool list{false};
    size_t payload_length{0};
};

inline constexpr uint8_t kEmptyStringCode{0x80};
inline constexpr uint8_t kEmptyListCode{0xC0};

void encode_header(Bytes& to, Header header);

void encode(Bytes& to, ByteView str);

template <UnsignedIntegral T>
void encode(Bytes& to, const T& n) {
    if (n == 0) {
        to.push_back(kEmptyStringCode);
    } else if (n < kEmptyStringCode) {
        to.push_back(static_cast<uint8_t>(n));
    } else {
        const ByteView be{endian::to_big_compact(n)};
        encode_header(to, {.list = false, .payload_length = be.size()});
        to.append(be);
    }
}

void encode(Bytes& to, bool);

size_t length_of_length(uint64_t payload_length) noexcept;

size_t length(ByteView) noexcept;

template <UnsignedIntegral T>
size_t length(const T& n) noexcept {
    if (n < kEmptyStringCode) {
        return 1;
    }
    const size_t n_bytes{intx::count_significant_bytes(n)};
    return n_bytes + length_of_length(n_bytes);
}

inline size_t length(bool) noexcept {
    return 1;
}

}  // namespace silkworm::rlp
