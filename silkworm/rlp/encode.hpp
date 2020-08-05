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

// RLP encoding functions as per
// https://eth.wiki/en/fundamentals/rlp

#ifndef SILKWORM_RLP_ENCODE_H_
#define SILKWORM_RLP_ENCODE_H_

#include <intx/intx.hpp>
#include <ostream>
#include <silkworm/common/base.hpp>
#include <vector>

namespace silkworm {

struct BlockBody;
struct BlockHeader;
struct Transaction;

namespace rlp {

static constexpr uint8_t kEmptyStringCode = 0x80;
static constexpr uint8_t kEmptyListCode = 0xC0;

struct Header {
  bool list{false};
  uint64_t payload_length{0};
};

void encode_header(std::ostream& to, Header header);

void encode(std::ostream& to, ByteView s);
void encode(std::ostream& to, uint64_t n);
void encode(std::ostream& to, const intx::uint256& n);

template <unsigned N>
void encode(std::ostream& to, const uint8_t (&bytes)[N]) {
  static_assert(N <= 55, "Complex RLP length encoding not supported");

  to.put(kEmptyStringCode + N);
  const void* ptr = bytes;
  to.write(static_cast<const char*>(ptr), N);
}

void encode(std::ostream& to, const BlockBody& block_body);
void encode(std::ostream& to, const BlockHeader& header);
void encode(std::ostream& to, const Transaction& txn);

size_t length_of_length(uint64_t payload_length);

size_t length(ByteView s);
size_t length(uint64_t n);
size_t length(const intx::uint256& n);

size_t length(const BlockHeader& header);
size_t length(const Transaction& transaction);

template <class T>
size_t length(const std::vector<T>& v) {
  size_t payload_length{0};
  for (const T& x : v) {
    payload_length += length(x);
  }
  return length_of_length(payload_length) + payload_length;
}

template <class T>
void encode(std::ostream& to, const std::vector<T>& v) {
  Header h{true, 0};
  for (const T& x : v) {
    h.payload_length += length(x);
  }
  encode_header(to, h);
  for (const T& x : v) {
    encode(to, x);
  }
}

// view of a thread-local buffer, must be consumed straight away
ByteView big_endian(uint64_t n);
ByteView big_endian(const intx::uint256& n);
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_RLP_ENCODE_H_
