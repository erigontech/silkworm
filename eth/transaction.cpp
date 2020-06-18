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
void Encode(std::ostream& to, const eth::Transaction& txn) {
  Header h{.list = true, .length = 0};
  h.length += Length(txn.nonce);
  h.length += Length(txn.gas_price);
  h.length += Length(txn.gas_limit);
  h.length += txn.to ? (eth::kAddressLength + 1) : 1;
  h.length += Length(txn.value);
  h.length += Length(txn.data);
  h.length += Length(txn.v);
  h.length += Length(txn.r);
  h.length += Length(txn.s);

  Encode(to, h);
  Encode(to, txn.nonce);
  Encode(to, txn.gas_price);
  Encode(to, txn.gas_limit);
  if (txn.to) {
    to.put(kAddressRlpCode);
    to.write(txn.to->data(), eth::kAddressLength);
  } else {
    to.put(kEmptyStringCode);
  }
  Encode(to, txn.value);
  Encode(to, txn.data);
  Encode(to, txn.v);
  Encode(to, txn.r);
  Encode(to, txn.s);
}

eth::Transaction DecodeTransaction(std::istream& from) {
  Header h = DecodeHeader(from);
  if (!h.list) {
    throw DecodingError("unexpected string");
  }

  eth::Transaction txn;
  txn.nonce = DecodeUint64(from);
  txn.gas_price = DecodeUint256(from);
  txn.gas_limit = DecodeUint64(from);

  uint8_t toCode = from.get();
  if (toCode == kAddressRlpCode) {
    eth::Address a;
    from.read(a.data(), eth::kAddressLength);
    txn.to = a;
  } else if (toCode != kEmptyStringCode) {
    throw DecodingError("unexpected code for txn.to");
  }

  txn.value = DecodeUint256(from);
  txn.data = DecodeString(from);
  txn.v = DecodeUint256(from);
  txn.r = DecodeUint256(from);
  txn.s = DecodeUint256(from);

  return txn;
}

}  // namespace rlp
}  // namespace silkworm
