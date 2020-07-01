/*
   Copyright 2020 The Silkworm Authors

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

namespace {

std::string_view big_endian(uint64_t n) {
  thread_local uint64_t buf;

  // We assume a little-endian architecture like amd64
  buf = intx::bswap(n);
  const char* p = reinterpret_cast<char*>(&buf);
  unsigned zero_bytes = intx::clz(n) / 8;
  return {p + zero_bytes, 8 - zero_bytes};
}

}  // namespace

namespace silkworm::rlp {

void encode_header(std::ostream& to, Header header) {
  if (header.length < 56) {
    uint8_t code = header.list ? kEmptyListCode : kEmptyStringCode;
    to.put(code + header.length);
  } else {
    std::string_view len_be = big_endian(header.length);
    uint8_t code = header.list ? '\xF7' : '\xB7';
    to.put(code + len_be.length());
    to.write(len_be.data(), len_be.length());
  }
}

size_t length_of_length(uint64_t length) {
  if (length < 56) {
    return 1;
  } else {
    return 1 + 8 - intx::clz(length) / 8;
  }
}

void encode(std::ostream& to, std::string_view s) {
  if (s.length() != 1 || static_cast<uint8_t>(s[0]) >= kEmptyStringCode) {
    encode_header(to, {.list = false, .length = s.length()});
  }
  to.write(s.data(), s.length());
}

size_t length(std::string_view s) {
  size_t len = s.length();
  if (s.length() != 1 || static_cast<uint8_t>(s[0]) >= kEmptyStringCode) {
    len += length_of_length(s.length());
  }
  return len;
}

void encode(std::ostream& to, uint64_t n) {
  if (n == 0) {
    to.put(kEmptyStringCode);
  } else if (n < kEmptyStringCode) {
    to.put(n);
  } else {
    std::string_view be = big_endian(n);
    to.put(kEmptyStringCode + be.length());
    to.write(be.data(), be.length());
  }
}

size_t length(uint64_t n) {
  if (n < kEmptyStringCode) {
    return 1;
  } else {
    return 1 + 8 - intx::clz(n) / 8;
  }
}

void encode(std::ostream& to, intx::uint256 n) {
  thread_local uint8_t buf[32];

  unsigned leading_zero_bits = clz(n);
  unsigned num_bits = 256 - leading_zero_bits;
  unsigned num_bytes = 32 - leading_zero_bits / 8;

  if (num_bits == 0) {
    to.put(kEmptyStringCode);
  } else if (num_bits <= 7) {
    to.put(intx::narrow_cast<char>(n));
  } else {
    to.put(kEmptyStringCode + num_bytes);
    intx::be::store(buf, n);
    const void* begin = buf + (32 - num_bytes);
    to.write(static_cast<const char*>(begin), num_bytes);
  }
}

size_t length(intx::uint256 n) {
  if (n < kEmptyStringCode) {
    return 1;
  } else {
    return 1 + 8 - intx::clz(n) / 8;
  }
}

}  // namespace silkworm::rlp
