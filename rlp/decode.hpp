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

#include <stddef.h>
#include <stdint.h>

#include <intx/intx.hpp>
#include <istream>
#include <string>

#include "encode.hpp"

namespace silkworm::rlp {

class DecodingError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Consumes RLP header unless it's a single byte in the [0x00, 0x7f] range,
// in which case the byte is put back.
Header decode_header(std::istream& from);

template <class T>
T decode(std::istream& from);

template <>
std::string decode(std::istream& from);

template <>
uint64_t decode(std::istream& from);

template <>
intx::uint256 decode(std::istream& from);

template <unsigned N>
void decode_bytes(std::istream& from, uint8_t (&to)[N]) {
  static_assert(N <= 55, "Complex RLP length encoding not supported");

  from.exceptions(std::ios_base::eofbit | std::ios_base::failbit | std::ios_base::badbit);

  uint8_t b = from.get();
  if (b != kEmptyStringCode + N) {
    throw DecodingError("unexpected length");
  }

  void* ptr = to;
  from.read(static_cast<char*>(ptr), N);
}

}  // namespace silkworm::rlp

#endif  // SILKWORM_RLP_DECODE_H_
