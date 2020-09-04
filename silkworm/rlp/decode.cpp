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

uint64_t read_uint64(ByteView be, bool allow_leading_zeros) {
  static constexpr size_t kMaxBytes{8};
  static_assert(sizeof(uint64_t) == kMaxBytes);

  if (be.length() > kMaxBytes) {
    throw DecodingError("uint64 overflow");
  }

  if (be.empty()) {
    return 0;
  }

  if (be[0] == 0 && !allow_leading_zeros) {
    throw DecodingError("leading zero(s)");
  }

  uint64_t buf{0};

  auto* p{reinterpret_cast<uint8_t*>(&buf)};
  std::memcpy(p + (kMaxBytes - be.length()), &be[0], be.length());

  static_assert(boost::endian::order::native == boost::endian::order::little,
                "We assume a little-endian architecture like amd64");
  return intx::bswap(buf);
}

intx::uint256 read_uint256(ByteView be, bool allow_leading_zeros) {
  static constexpr size_t kMaxBytes{32};
  static_assert(sizeof(intx::uint256) == kMaxBytes);

  if (be.length() > kMaxBytes) {
    throw DecodingError("uint256 overflow");
  }

  if (be.empty()) {
    return 0;
  }

  if (be[0] == 0 && !allow_leading_zeros) {
    throw DecodingError("leading zero(s)");
  }

  intx::uint256 buf{0};

  uint8_t* p{as_bytes(buf)};
  std::memcpy(p + (kMaxBytes - be.length()), &be[0], be.length());

  static_assert(boost::endian::order::native == boost::endian::order::little);
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
  to = read_uint64(from.substr(0, h.payload_length));
  from.remove_prefix(h.payload_length);
}

template <>
void decode(ByteView& from, intx::uint256& to) {
  Header h{decode_header(from)};
  if (h.list) {
    throw DecodingError("unexpected list");
  }
  to = read_uint256(from.substr(0, h.payload_length));
  from.remove_prefix(h.payload_length);
}
}  // namespace silkworm::rlp
