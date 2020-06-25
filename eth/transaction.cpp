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

#include "../rlp/decode.hpp"
#include "../rlp/encode.hpp"
#include "common.hpp"

namespace {
static constexpr uint8_t kAddressRlpCode =
    silkworm::rlp::kEmptyStringCode + silkworm::eth::kAddressLength;
}

namespace silkworm {

namespace eth {

bool operator==(const Transaction& a, const Transaction& b) {
  return a.nonce == b.nonce && a.gas_price == b.gas_price && a.gas_limit == b.gas_limit &&
         a.to == b.to && a.value == b.value && a.data == b.data && a.v == b.v && a.r == b.r &&
         a.s == b.s;
}

}  // namespace eth

namespace rlp {
void encode(std::ostream& to, const eth::Transaction& txn) {
  Header h{.list = true, .length = 0};
  h.length += length(txn.nonce);
  h.length += length(txn.gas_price);
  h.length += length(txn.gas_limit);
  h.length += txn.to ? (eth::kAddressLength + 1) : 1;
  h.length += length(txn.value);
  h.length += length(txn.data);
  h.length += length(txn.v);
  h.length += length(txn.r);
  h.length += length(txn.s);

  encode(to, h);
  encode(to, txn.nonce);
  encode(to, txn.gas_price);
  encode(to, txn.gas_limit);
  if (txn.to) {
    to.put(kAddressRlpCode);
    const void* ptr = txn.to->bytes;
    to.write(static_cast<const char*>(ptr), eth::kAddressLength);
  } else {
    to.put(kEmptyStringCode);
  }
  encode(to, txn.value);
  encode(to, txn.data);
  encode(to, txn.v);
  encode(to, txn.r);
  encode(to, txn.s);
}

eth::Transaction decode_transaction(std::istream& from) {
  Header h = decode_header(from);
  if (!h.list) {
    throw DecodingError("unexpected string");
  }

  eth::Transaction txn;
  txn.nonce = decode_uint64(from);
  txn.gas_price = decode_uint256(from);
  txn.gas_limit = decode_uint64(from);

  uint8_t toCode = from.get();
  if (toCode == kAddressRlpCode) {
    evmc::address a;
    void* ptr = a.bytes;
    from.read(static_cast<char*>(ptr), eth::kAddressLength);
    txn.to = a;
  } else if (toCode != kEmptyStringCode) {
    throw DecodingError("unexpected code for txn.to");
  }

  txn.value = decode_uint256(from);
  txn.data = decode_string(from);
  txn.v = decode_uint256(from);
  txn.r = decode_uint256(from);
  txn.s = decode_uint256(from);

  return txn;
}

}  // namespace rlp
}  // namespace silkworm
