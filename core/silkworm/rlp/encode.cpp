/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "encode.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::rlp {

void encode_header(Bytes& to, Header header) {
    if (header.payload_length < 56) {
        const uint8_t code{header.list ? kEmptyListCode : kEmptyStringCode};
        to.push_back(static_cast<uint8_t>(code + header.payload_length));
    } else {
        auto len_be{endian::to_big_compact(header.payload_length)};
        const uint8_t code = header.list ? 0xF7 : 0xB7;
        to.push_back(static_cast<uint8_t>(code + len_be.length()));
        to.append(len_be);
    }
}

size_t length_of_length(uint64_t payload_length) {
    if (payload_length < 56) {
        return 1;
    } else {
        return 1 + 8 - intx::clz(payload_length) / 8;
    }
}

void encode(Bytes& to, ByteView s) {
    if (s.length() != 1 || s[0] >= kEmptyStringCode) {
        encode_header(to, {false, s.length()});
    }
    to.append(s);
}

size_t length(ByteView s) {
    size_t len{s.length()};
    if (s.length() != 1 || s[0] >= kEmptyStringCode) {
        len += length_of_length(s.length());
    }
    return len;
}

void encode(Bytes& to, uint64_t n) {
    if (n == 0) {
        to.push_back(kEmptyStringCode);
    } else if (n < kEmptyStringCode) {
        to.push_back(static_cast<uint8_t>(n));
    } else {
        auto be{endian::to_big_compact(n)};
        to.push_back(static_cast<uint8_t>(kEmptyStringCode + be.length()));
        to.append(be);
    }
}

size_t length(uint64_t n) noexcept {
    if (n < kEmptyStringCode) {
        return 1;
    } else {
        return 1 + 8 - intx::clz(n) / 8;
    }
}

void encode(Bytes& to, const intx::uint256& n) {
    if (n == 0) {
        to.push_back(kEmptyStringCode);
    } else if (n < kEmptyStringCode) {
        to.push_back(static_cast<uint8_t>(n));
    } else {
        auto be{endian::to_big_compact(n)};
        to.push_back(static_cast<uint8_t>(kEmptyStringCode + be.length()));
        to.append(be);
    }
}

size_t length(const intx::uint256& n) {
    if (n < kEmptyStringCode) {
        return 1;
    } else {
        return 1 + 32 - intx::clz(n) / 8;
    }
}

}  // namespace silkworm::rlp
