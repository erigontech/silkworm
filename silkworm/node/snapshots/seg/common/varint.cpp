/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "varint.hpp"

namespace silkworm::snapshots::seg::varint {

constexpr size_t kMaxVarintBytes = 10;
constexpr uint8_t kByteMask = 0b01111111;
constexpr uint8_t kContMask = 0b10000000;
constexpr uint8_t kByteMaskBits = 7;

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

    for (i = 0, offset = 0; (i < data.size()) && (i < kMaxVarintBytes) && !found_last; i++, offset += kByteMaskBits) {
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
