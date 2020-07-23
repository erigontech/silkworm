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

#include <silkworm/rlp/encode.hpp>

namespace silkworm {

namespace rlp {

static Header rlp_header(const BlockHeader& header) {
  Header rlp_head{.list = true, .payload_length = 6 * (kHashLength + 1)};
  rlp_head.payload_length += kAddressLength + 1;  // beneficiary
  rlp_head.payload_length += kBloomByteLength + length_of_length(kBloomByteLength);
  rlp_head.payload_length += length(header.difficulty);
  rlp_head.payload_length += length(header.number);
  rlp_head.payload_length += length(header.gas_limit);
  rlp_head.payload_length += length(header.gas_used);
  rlp_head.payload_length += length(header.timestamp);
  rlp_head.payload_length += length(header.extra_data());
  rlp_head.payload_length += 8 + 1;  // nonce
  return rlp_head;
}

size_t length(const BlockHeader& header) {
  Header rlp_head = rlp_header(header);
  return length_of_length(rlp_head.payload_length) + rlp_head.payload_length;
}

void encode(std::ostream& to, const BlockHeader& header) {
  encode_header(to, rlp_header(header));
  encode(to, header.parent_hash.bytes);
  encode(to, header.ommers_hash.bytes);
  encode(to, header.beneficiary.bytes);
  encode(to, header.state_root.bytes);
  encode(to, header.transactions_root.bytes);
  encode(to, header.receipts_root.bytes);
  encode_header(to, {.list = false, .payload_length = kBloomByteLength});
  to.write(byte_ptr_cast(header.logs_bloom.data()), kBloomByteLength);
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
void decode(std::istream& from, BlockHeader& to) {
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
  if (bloom_head.list || bloom_head.payload_length != kBloomByteLength) {
    throw DecodingError("unorthodox logsBloom");
  }
  from.read(byte_ptr_cast(to.logs_bloom.data()), kBloomByteLength);

  decode(from, to.difficulty);
  decode(from, to.number);
  decode(from, to.gas_limit);
  decode(from, to.gas_used);
  decode(from, to.timestamp);

  Header extra_data_head = decode_header(from);
  if (extra_data_head.list) {
    throw DecodingError("extraData may not be list");
  }
  if (extra_data_head.payload_length > 32) {
    throw DecodingError("extraData must be no longer than 32 bytes");
  }
  to.extra_data_size_ = extra_data_head.payload_length;
  from.read(byte_ptr_cast(to.extra_data_.bytes), to.extra_data_size_);

  decode(from, to.mix_hash.bytes);
  decode(from, to.nonce);
}

void encode(std::ostream& to, const BlockBody& block_body) {
  Header rlp_head{.list = true, .payload_length = 0};
  rlp_head.payload_length += length(block_body.transactions);
  rlp_head.payload_length += length(block_body.ommers);
  encode_header(to, rlp_head);
  encode(to, block_body.transactions);
  encode(to, block_body.ommers);
}

template <>
void decode(std::istream& from, BlockBody& to) {
  Header rlp_head = decode_header(from);
  if (!rlp_head.list) {
    throw DecodingError("unexpected string");
  }

  decode_vector(from, to.transactions);
  decode_vector(from, to.ommers);
}
}  // namespace rlp
}  // namespace silkworm
