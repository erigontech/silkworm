/*
   Copyright 2020-2022 The Silkworm Authors

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

// RLP encoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#pragma once

#include <optional>
#include <vector>

#include <intx/intx.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/endian.hpp>

namespace silkworm::rlp {

struct Header {
    bool list{false};
    size_t payload_length{0};
};

inline constexpr uint8_t kEmptyStringCode{0x80};
inline constexpr uint8_t kEmptyListCode{0xC0};

void encode_header(Bytes& to, Header header);

void encode(Bytes& to, ByteView);

template <UnsignedIntegral T>
void encode(Bytes& to, const T& n) {
    if (n == 0) {
        to.push_back(kEmptyStringCode);
    } else if (n < kEmptyStringCode) {
        to.push_back(static_cast<uint8_t>(n));
    } else {
        const ByteView be{endian::to_big_compact(n)};
        encode_header(to, {.list = false, .payload_length = be.length()});
        to.append(be);
    }
}

template <>
void encode(Bytes& to, const bool&);

size_t length_of_length(uint64_t payload_length) noexcept;

size_t length(ByteView) noexcept;

template <UnsignedIntegral T>
size_t length(const T& n) noexcept {
    if (n < kEmptyStringCode) {
        return 1;
    } else {
        const size_t n_bytes{intx::count_significant_bytes(n)};
        return n_bytes + length_of_length(n_bytes);
    }
}

template <>
inline size_t length(const bool&) noexcept {
    return 1;
}

}  // namespace silkworm::rlp
