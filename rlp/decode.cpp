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

#include "decode.hpp"

#include <gsl/gsl_assert>

namespace {

uint64_t read_uint64(std::istream& from, size_t len) {
  Expects(len <= 8);

  if (len == 0) {
    return 0;
  }

  if (from.peek() == 0) {
    throw silkworm::rlp::DecodingError("leading zero(s)");
  }

  thread_local uint64_t buf;

  buf = 0;
  char* p = reinterpret_cast<char*>(&buf);
  from.read(p + (8 - len), len);

  // We assume a little-endian architecture like amd64
  return intx::bswap(buf);
}

}  // namespace

namespace silkworm::rlp {

Header decode_header(std::istream& from) {
  from.exceptions(std::ios_base::eofbit | std::ios_base::failbit | std::ios_base::badbit);

  Header h;
  uint8_t b = from.get();
  if (b < 0x80) {
    from.unget();
    h.length = 1;
  } else if (b < 0xB8) {
    h.length = b - 0x80;
    if (h.length == 1 && static_cast<uint8_t>(from.peek()) < 0x80) {
      throw DecodingError("non-canonical single byte");
    }
  } else if (b < 0xC0) {
    h.length = read_uint64(from, b - 0xB7);
    if (h.length < 56) {
      throw DecodingError("non-canonical size");
    }
  } else if (b < 0xF8) {
    h.list = true;
    h.length = b - 0xC0;
  } else {
    h.list = true;
    h.length = read_uint64(from, b - 0xF7);
    if (h.length < 56) {
      throw DecodingError("non-canonical size");
    }
  }
  return h;
}

template <>
void decode(std::istream& from, std::string& to) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.length > kMaxStringSize) {
    throw DecodingError("string is too long");
  }
  to.resize(h.length);
  from.read(to.data(), h.length);
}

template <>
void decode(std::istream& from, uint64_t& to) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.length > 8) {
    throw DecodingError("uint64 overflow");
  }
  to = read_uint64(from, h.length);
}

template <>
void decode(std::istream& from, intx::uint256& to) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.length > 32) {
    throw DecodingError("uint256 overflow");
  }

  if (h.length == 0) {
    to = 0;
    return;
  }

  if (from.peek() == 0) {
    throw silkworm::rlp::DecodingError("leading zero(s)");
  }

  thread_local intx::uint256 buf;

  buf = 0;
  char* p = reinterpret_cast<char*>(as_bytes(buf));
  from.read(p + (32 - h.length), h.length);

  to = intx::bswap(buf);
}

}  // namespace silkworm::rlp
