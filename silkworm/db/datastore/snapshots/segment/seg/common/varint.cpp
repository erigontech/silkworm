// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "varint.hpp"

namespace silkworm::snapshots::seg::varint {

static constexpr size_t kMaxVarintBytes = 10;
static constexpr uint8_t kByteMask = 0b01111111;
static constexpr uint8_t kContMask = 0b10000000;
static constexpr uint8_t kByteMaskBits = 7;

ByteView encode(Bytes& out, uint64_t value) {
    out.reserve(kMaxVarintBytes);
    out.resize(0);

    uint8_t cont_mask{};
    do {
        cont_mask = (value > kByteMask) ? kContMask : 0;
        out.push_back((static_cast<uint8_t>(value) & kByteMask) | cont_mask);
        value >>= kByteMaskBits;
    } while (cont_mask);

    return out;
}

std::optional<uint64_t> decode(ByteView& data) {
    uint64_t value = 0;
    size_t i{}, offset{};
    bool found_last = false;

    for (i = 0, offset = 0; (i < data.size()) && (i < kMaxVarintBytes) && !found_last; ++i, offset += kByteMaskBits) {
        value |= static_cast<uint64_t>(data[i] & kByteMask) << offset;
        if (data[i] <= kByteMask) {
            found_last = true;
        }
    }

    if (found_last) {
        data.remove_prefix(i);
        return value;
    }
    return std::nullopt;
}

std::optional<ByteView> read(Bytes& out, absl::FunctionRef<char()> get_char) {
    out.reserve(kMaxVarintBytes);
    out.resize(0);

    bool found_last = false;
    do {
        auto c = static_cast<uint8_t>(get_char());
        out.push_back(c);
        found_last = !(c & kContMask);
    } while ((out.size() < kMaxVarintBytes) && !found_last);

    if (found_last) {
        return out;
    }
    return std::nullopt;
}

}  // namespace silkworm::snapshots::seg::varint
