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

#include "account.hpp"

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/decode.hpp>

namespace silkworm {

bool operator==(const Account& a, const Account& b) {
  return a.nonce == b.nonce && a.balance == b.balance && a.storage_root == b.storage_root &&
         a.code_hash == b.code_hash && a.incarnation == b.incarnation;
}

Bytes Account::encode_for_storage(bool omit_code_hash) const {
  Bytes res(1, '\0');
  uint8_t field_set{0};

  if (nonce != 0) {
    field_set = 1;
    ByteView be{rlp::big_endian(nonce)};
    res.push_back(be.length());
    res.append(be);
  }

  if (balance != 0) {
    field_set |= 2;
    ByteView be{rlp::big_endian(balance)};
    res.push_back(be.length());
    res.append(be);
  }

  if (incarnation != 0) {
    field_set |= 4;
    ByteView be{rlp::big_endian(incarnation)};
    res.push_back(be.length());
    res.append(be);
  }

  if (code_hash != kEmptyHash && !omit_code_hash) {
    field_set |= 8;
    res.push_back(kHashLength);
    res.append(code_hash.bytes, kHashLength);
  }

  res[0] = field_set;
  return res;
}

Account decode_account_from_storage(ByteView encoded) {
  Account a{};
  if (encoded.empty()) return a;

  uint8_t field_set = encoded[0];
  size_t pos{1};

  if (field_set & 1) {
    uint8_t len = encoded[pos++];
    if (encoded.length() < pos + len) {
      throw DecodingError("input too short for account nonce");
    }
    a.nonce = rlp::read_uint64(encoded.substr(pos, len));
    pos += len;
  }

  if (field_set & 2) {
    uint8_t len = encoded[pos++];
    if (encoded.length() < pos + len) {
      throw DecodingError("input too short for account balance");
    }
    std::memcpy(&as_bytes(a.balance)[32 - len], &encoded[pos], len);
    a.balance = bswap(a.balance);
    pos += len;
  }

  if (field_set & 4) {
    uint8_t len = encoded[pos++];
    if (encoded.length() < pos + len) {
      throw DecodingError("input too short for account incarnation");
    }
    a.incarnation = rlp::read_uint64(encoded.substr(pos, len));
    pos += len;
  }

  if (field_set & 8) {
    uint8_t len = encoded[pos++];
    if (len != kHashLength) {
      throw DecodingError("codeHash should be 32 bytes long,");
    }
    if (encoded.length() < pos + len) {
      throw DecodingError("input too short for account codeHash");
    }
    std::memcpy(a.code_hash.bytes, &encoded[pos], kHashLength);
  }

  return a;
}

namespace rlp {

void encode(Bytes& to, const Account& account) {
  Header h{true, 0};
  h.payload_length += length(account.nonce);
  h.payload_length += length(account.balance);
  h.payload_length += kHashLength + 1;
  h.payload_length += kHashLength + 1;

  encode_header(to, h);
  encode(to, account.nonce);
  encode(to, account.balance);
  encode(to, account.storage_root.bytes);
  encode(to, account.code_hash.bytes);
}

template <>
void decode(ByteView& from, Account& to) {
  Header h = decode_header(from);
  if (!h.list) {
    throw DecodingError("unexpected string");
  }

  decode(from, to.nonce);
  decode(from, to.balance);
  decode(from, to.storage_root.bytes);
  decode(from, to.code_hash.bytes);
}
}  // namespace rlp
}  // namespace silkworm
