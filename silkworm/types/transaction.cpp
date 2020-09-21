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

#include <cstring>
#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/crypto/ecdsa.hpp>
#include <silkworm/rlp/encode.hpp>
namespace silkworm {

bool operator==(const Transaction& a, const Transaction& b) {
  return a.nonce == b.nonce && a.gas_price == b.gas_price && a.gas_limit == b.gas_limit &&
         a.to == b.to && a.value == b.value && a.data == b.data && a.v == b.v && a.r == b.r &&
         a.s == b.s;
}

namespace rlp {

static Header rlp_header(const Transaction& txn, bool for_signing) {
  Header h{true, 0};
  h.payload_length += length(txn.nonce);
  h.payload_length += length(txn.gas_price);
  h.payload_length += length(txn.gas_limit);
  h.payload_length += txn.to ? (kAddressLength + 1) : 1;
  h.payload_length += length(txn.value);
  h.payload_length += length(txn.data);
  if (!for_signing) {
    h.payload_length += length(txn.v);
    h.payload_length += length(txn.r);
    h.payload_length += length(txn.s);
  }
  return h;
}

size_t length(const Transaction& txn) {
  Header rlp_head = rlp_header(txn, /*for_signing=*/false);
  return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
}

// TODO(Andrew) EIP-155; unify with Andrea's work
static void encode(Bytes& to, const Transaction& txn, bool for_signing) {
  encode_header(to, rlp_header(txn, for_signing));
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
  if (!for_signing) {
    encode(to, txn.v);
    encode(to, txn.r);
    encode(to, txn.s);
  }
}

void encode(Bytes& to, const Transaction& txn) { encode(to, txn, /*for_signing=*/false); }

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

// TODO(Andrew) EIP-155; unify with Andrea's work
void Transaction::recover_sender() {
  // TODO(Andrew) inputs_are_valid

  Bytes rlp{};
  rlp::encode(rlp, *this, /*for_signing=*/true);
  ethash::hash256 hash{ethash::keccak256(rlp.data(), rlp.size())};

  uint8_t signature[32 * 2];
  intx::be::unsafe::store(signature, r);
  intx::be::unsafe::store(signature + 32, s);

  std::optional<Bytes> recovered{ecdsa::recover(full_view(hash.bytes), full_view(signature),
                                                intx::narrow_cast<uint8_t>(v - 27))};
  if (recovered) {
    hash = ethash::keccak256(recovered->data() + 1, recovered->length() - 1);
    from = evmc::address{};
    std::memcpy(from->bytes, &hash.bytes[12], 32 - 12);
  }
}
}  // namespace silkworm
