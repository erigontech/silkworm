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

// RLP decoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#ifndef SILKWORM_RLP_DECODE_H_
#define SILKWORM_RLP_DECODE_H_

#include <cstring>
#include <intx/intx.hpp>
#include <silkworm/common/base.hpp>
#include <silkworm/rlp/encode.hpp>
#include <vector>

namespace silkworm::rlp {

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
Header decode_header(ByteView& from);

template <class T>
void decode(ByteView& from, T& to);

template <>
void decode(ByteView& from, Bytes& to);

template <>
void decode(ByteView& from, uint64_t& to);

template <>
void decode(ByteView& from, intx::uint256& to);

template <unsigned N>
void decode(ByteView& from, uint8_t (&to)[N]) {
  static_assert(N <= 55, "Complex RLP length encoding not supported");

  if (from.length() < N + 1) {
    throw DecodingError("input too short");
  }

  if (from[0] != kEmptyStringCode + N) {
    throw DecodingError("unexpected length");
  }

  std::memcpy(to, &from[1], N);
  from.remove_prefix(N + 1);
}

template <class T>
void decode_vector(ByteView& from, std::vector<T>& to) {
  Header h{decode_header(from)};
  if (!h.list) {
    throw DecodingError("unexpected string");
  }

  to.clear();

  ByteView payload_view{from.substr(0, h.payload_length)};
  while (!payload_view.empty()) {
    to.emplace_back();
    decode(payload_view, to.back());
  }

  from.remove_prefix(h.payload_length);
}

uint64_t read_uint64(ByteView big_endian, bool allow_leading_zeros = false);

intx::uint256 read_uint256(ByteView big_endian, bool allow_leading_zeros = false);

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_DECODE_H_
