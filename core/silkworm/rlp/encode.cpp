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
#include <silkworm/common/util.hpp>

namespace silkworm::rlp {

void encode_header(Bytes& to, Header header) {
    if (header.payload_length < 56) {
        uint8_t code{header.list ? kEmptyListCode : kEmptyStringCode};
        to.push_back(static_cast<uint8_t>(code + header.payload_length));
    } else {
        ByteView len_be{big_endian(header.payload_length)};
        uint8_t code = header.list ? '\xF7' : '\xB7';
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

void encode(Bytes& to, const evmc::bytes32& hash) {
    to.push_back(kEmptyStringCode + kHashLength);
    to.append(full_view(hash));
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
        ByteView be{big_endian(n)};
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
        ByteView be{big_endian(n)};
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

ByteView big_endian(uint64_t n) {
    thread_local uint64_t buf;

    static_assert(SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN, "We assume a little-endian architecture like amd64");
    buf = intx::bswap(n);
    const uint8_t* p{reinterpret_cast<uint8_t*>(&buf)};
    unsigned zero_bytes = intx::clz(n) / 8;
    return {p + zero_bytes, 8 - zero_bytes};
}

ByteView big_endian(const intx::uint256& n) {
    thread_local uint8_t buf[32];

    intx::be::store(buf, n);
    unsigned zero_bytes = intx::clz(n) / 8;
    return {buf + zero_bytes, 32 - zero_bytes};
}

}  // namespace silkworm::rlp
