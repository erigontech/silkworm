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

#include <boost/endian/conversion.hpp>
#include <cassert>
#include <silkworm/common/util.hpp>

namespace silkworm::rlp {

uint64_t read_uint64(ByteView from) {
  assert(from.length() <= 8);

  if (from.empty()) {
    return 0;
  }

  if (from[0] == 0) {
    throw DecodingError("leading zero(s)");
  }

  thread_local uint64_t buf;

  buf = 0;
  auto* p{reinterpret_cast<uint8_t*>(&buf)};
  std::memcpy(p + (8 - from.length()), &from[0], from.length());

  static_assert(boost::endian::order::native == boost::endian::order::little,
                "We assume a little-endian architecture like amd64");
  return intx::bswap(buf);
}

Header decode_header(ByteView& from) {
  if (from.empty()) {
    throw DecodingError("input too short");
  }

  Header h{};
  uint8_t b{from[0]};
  if (b < 0x80) {
    h.payload_length = 1;
  } else if (b < 0xB8) {
    from.remove_prefix(1);
    h.payload_length = b - 0x80;
    if (h.payload_length == 1) {
      if (from.empty()) {
        throw DecodingError("input too short");
      }
      if (from[0] < 0x80) {
        throw DecodingError("non-canonical single byte");
      }
    }
  } else if (b < 0xC0) {
    from.remove_prefix(1);
    size_t len_of_len{b - 0xB7u};
    if (from.length() < len_of_len) {
      throw DecodingError("input too short");
    }
    h.payload_length = read_uint64(from.substr(0, len_of_len));
    from.remove_prefix(len_of_len);
    if (h.payload_length < 56) {
      throw DecodingError("non-canonical size");
    }
  } else if (b < 0xF8) {
    from.remove_prefix(1);
    h.list = true;
    h.payload_length = b - 0xC0;
  } else {
    from.remove_prefix(1);
    h.list = true;
    size_t len_of_len{b - 0xF7u};
    if (from.length() < len_of_len) {
      throw DecodingError("input too short");
    }
    h.payload_length = read_uint64(from.substr(0, len_of_len));
    from.remove_prefix(len_of_len);
    if (h.payload_length < 56) {
      throw DecodingError("non-canonical size");
    }
  }

  if (from.length() < h.payload_length) {
    throw DecodingError("input too short");
  }

  return h;
}

template <>
void decode(ByteView& from, Bytes& to) {
  Header h = decode_header(from);
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  to = from.substr(0, h.payload_length);
  from.remove_prefix(h.payload_length);
}

template <>
void decode(ByteView& from, uint64_t& to) {
  Header h{decode_header(from)};
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.payload_length > 8) {
    throw DecodingError("uint64 overflow");
  }

  to = read_uint64(from.substr(0, h.payload_length));
  from.remove_prefix(h.payload_length);
}

template <>
void decode(ByteView& from, intx::uint256& to) {
  Header h{decode_header(from)};

  if (h.list) {
    throw DecodingError("unexpected list");
  }
  if (h.payload_length > 32) {
    throw DecodingError("uint256 overflow");
  }

  if (h.payload_length == 0) {
    to = 0;
    return;
  }

  if (from[0] == 0) {
    throw DecodingError("leading zero(s)");
  }

  thread_local intx::uint256 buf;

  buf = 0;
  std::memcpy(as_bytes(buf) + (32 - h.payload_length), &from[0], h.payload_length);
  to = intx::bswap(buf);

  from.remove_prefix(h.payload_length);
}
}  // namespace silkworm::rlp
