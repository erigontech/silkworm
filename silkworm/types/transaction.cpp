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

#include "transaction.hpp"

#include <silkworm/common/base.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm {

bool operator==(const Transaction& a, const Transaction& b) {
  return a.nonce == b.nonce && a.gas_price == b.gas_price && a.gas_limit == b.gas_limit &&
         a.to == b.to && a.value == b.value && a.data == b.data && a.v == b.v && a.r == b.r &&
         a.s == b.s;
}

namespace rlp {

static Header rlp_header(const Transaction& txn) {
  Header h{true, 0};
  h.payload_length += length(txn.nonce);
  h.payload_length += length(txn.gas_price);
  h.payload_length += length(txn.gas_limit);
  h.payload_length += txn.to ? (kAddressLength + 1) : 1;
  h.payload_length += length(txn.value);
  h.payload_length += length(txn.data);
  h.payload_length += length(txn.v);
  h.payload_length += length(txn.r);
  h.payload_length += length(txn.s);
  return h;
}

size_t length(const Transaction& txn) {
  Header rlp_head = rlp_header(txn);
  return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
}

void encode(Bytes& to, const Transaction& txn) {
  encode_header(to, rlp_header(txn));
  encode(to, txn.nonce);
  encode(to, txn.gas_price);
  encode(to, txn.gas_limit);
  if (txn.to) {
    encode(to, txn.to->bytes);
  } else {
    to.push_back(kEmptyStringCode);
  }
  encode(to, txn.value);
  encode(to, txn.data);
  encode(to, txn.v);
  encode(to, txn.r);
  encode(to, txn.s);
}

template <>
void decode(ByteView& from, Transaction& to) {
  Header h{decode_header(from)};
  if (!h.list) {
    throw DecodingError("unexpected string");
  }

  decode(from, to.nonce);
  decode(from, to.gas_price);
  decode(from, to.gas_limit);

  if (from[0] == kEmptyStringCode) {
    to.to = {};
    from.remove_prefix(1);
  } else {
    to.to = evmc::address{};
    decode(from, to.to->bytes);
  }

  decode(from, to.value);
  decode(from, to.data);
  decode(from, to.v);
  decode(from, to.r);
  decode(from, to.s);
}
}  // namespace rlp
}  // namespace silkworm
