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

#include <intx/intx.hpp>
#include <istream>
#include <silkworm/common/base.hpp>
#include <silkworm/rlp/encode.hpp>
#include <vector>

namespace silkworm::rlp {

constexpr size_t kMaxStringSize = 1024 * 1024;

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
Header decode_header(std::istream& from);

template <class T>
void decode(std::istream& from, T& to);

template <>
void decode(std::istream& from, Bytes& to);

template <>
void decode(std::istream& from, uint64_t& to);

template <>
void decode(std::istream& from, intx::uint256& to);

template <unsigned N>
void decode(std::istream& from, uint8_t (&to)[N]) {
  static_assert(N <= 55, "Complex RLP length encoding not supported");

  from.exceptions(std::ios_base::eofbit | std::ios_base::failbit | std::ios_base::badbit);

  uint8_t b = from.get();
  if (b != kEmptyStringCode + N) {
    throw DecodingError("unexpected length");
  }

  void* ptr = to;
  from.read(static_cast<char*>(ptr), N);
}

template <class T>
void decode_vector(std::istream& from, std::vector<T>& to) {
  Header h = decode_header(from);
  if (!h.list) throw DecodingError("unexpected string");

  to.clear();

  int64_t end{from.tellg()};
  end += h.payload_length;

  while (from.tellg() < end) {
    to.emplace_back();
    decode(from, to.back());
  }

  if (from.tellg() != end) throw DecodingError("list length mismatch");
}

uint64_t read_uint64(std::istream& from, size_t len);
}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_DECODE_H_
