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

#include "block.hpp"

#include "rlp/encode.hpp"

namespace silkworm {

namespace rlp {

void encode(std::ostream& to, const eth::BlockHeader& header) {
  Header rlp_head{.list = true, .length = 6 * (eth::kHashLength + 1)};
  rlp_head.length += eth::kAddressLength + 1;  // beneficiary
  rlp_head.length += eth::kBloomByteLength + length_of_length(eth::kBloomByteLength);
  rlp_head.length += length(header.difficulty);
  rlp_head.length += length(header.number);
  rlp_head.length += length(header.gas_limit);
  rlp_head.length += length(header.gas_used);
  rlp_head.length += length(header.timestamp);
  rlp_head.length += length(header.extra_data());
  rlp_head.length += 8 + 1;  // nonce

  encode_header(to, rlp_head);
  encode(to, header.parent_hash.bytes);
  encode(to, header.ommers_hash.bytes);
  encode(to, header.beneficiary.bytes);
  encode(to, header.state_root.bytes);
  encode(to, header.transactions_root.bytes);
  encode(to, header.receipts_root.bytes);
  encode_header(to, {.list = false, .length = eth::kBloomByteLength});
  to.write(eth::byte_pointer_cast(header.logs_bloom.data()), eth::kBloomByteLength);
  encode(to, header.difficulty);
  encode(to, header.number);
  encode(to, header.gas_limit);
  encode(to, header.gas_used);
  encode(to, header.timestamp);
  encode(to, header.extra_data());
  encode(to, header.mix_hash.bytes);
  encode(to, header.nonce);
}

template <>
void decode(std::istream& from, eth::BlockHeader& to) {
  Header rlp_head = decode_header(from);
  if (!rlp_head.list) {
    throw DecodingError("unexpected string");
  }

  decode(from, to.parent_hash.bytes);
  decode(from, to.ommers_hash.bytes);
  decode(from, to.beneficiary.bytes);
  decode(from, to.state_root.bytes);
  decode(from, to.transactions_root.bytes);
  decode(from, to.receipts_root.bytes);

  Header bloom_head = decode_header(from);
  if (bloom_head.list || bloom_head.length != eth::kBloomByteLength) {
    throw DecodingError("unorthodox logsBloom");
  }
  from.read(eth::byte_pointer_cast(to.logs_bloom.data()), eth::kBloomByteLength);

  decode(from, to.difficulty);
  decode(from, to.number);
  decode(from, to.gas_limit);
  decode(from, to.gas_used);
  decode(from, to.timestamp);

  Header extra_data_head = decode_header(from);
  if (extra_data_head.list) {
    throw DecodingError("extraData may not be list");
  }
  if (extra_data_head.length > 32) {
    throw DecodingError("extraData must be no longer than 32 bytes");
  }
  to.extra_data_size_ = extra_data_head.length;
  from.read(eth::byte_pointer_cast(to.extra_data_.bytes), to.extra_data_size_);

  decode(from, to.mix_hash.bytes);
  decode(from, to.nonce);
}

}  // namespace rlp

}  // namespace silkworm
