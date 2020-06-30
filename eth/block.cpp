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

#include "../rlp/decode.hpp"
#include "../rlp/encode.hpp"
#include "common.hpp"

namespace silkworm {

namespace rlp {

void encode(std::ostream& to, const eth::BlockHeader& header) {
  Header bloom_head{.list = false, .length = eth::kBloomByteLength};

  Header rlp_head{.list = true, .length = 6 * (eth::kHashLength + 1)};
  rlp_head.length += eth::kAddressLength + 1;  // beneficiary
  rlp_head.length += eth::kBloomByteLength + length(bloom_head);
  rlp_head.length += length(header.difficulty);
  rlp_head.length += length(header.number);
  rlp_head.length += length(header.gas_limit);
  rlp_head.length += length(header.gas_used);
  rlp_head.length += length(header.timestamp);
  rlp_head.length += length(header.extra_data);
  rlp_head.length += 8 + 1;  // nonce

  encode(to, rlp_head);
  encode(to, header.parent_hash.bytes);
  encode(to, header.ommers_hash.bytes);
  encode(to, header.beneficiary.bytes);
  encode(to, header.state_root.bytes);
  encode(to, header.transactions_root.bytes);
  encode(to, header.receipts_root.bytes);
  encode(to, bloom_head);
  to.write(eth::byte_pointer_cast(header.logs_bloom.data()), eth::kBloomByteLength);
  encode(to, header.difficulty);
  encode(to, header.number);
  encode(to, header.gas_limit);
  encode(to, header.gas_used);
  encode(to, header.timestamp);
  encode(to, header.extra_data);
  encode(to, header.mix_hash.bytes);
  encode(to, header.nonce);
}

eth::BlockHeader decode_block_header(std::istream& from) {
  Header rlp_head = decode_header(from);
  if (!rlp_head.list) {
    throw DecodingError("unexpected string");
  }

  eth::BlockHeader header;
  decode_bytes(from, header.parent_hash.bytes);
  decode_bytes(from, header.ommers_hash.bytes);
  decode_bytes(from, header.beneficiary.bytes);
  decode_bytes(from, header.state_root.bytes);
  decode_bytes(from, header.transactions_root.bytes);
  decode_bytes(from, header.receipts_root.bytes);

  Header bloom_head = decode_header(from);
  if (bloom_head.list || bloom_head.length != eth::kBloomByteLength) {
    throw DecodingError("unorthodox logsBloom");
  }
  from.read(eth::byte_pointer_cast(header.logs_bloom.data()), eth::kBloomByteLength);

  header.difficulty = decode_uint256(from);
  header.number = decode_uint64(from);
  header.gas_limit = decode_uint64(from);
  header.gas_used = decode_uint64(from);
  header.timestamp = decode_uint64(from);
  header.extra_data = decode_string(from);
  decode_bytes(from, header.mix_hash.bytes);
  decode_bytes(from, header.nonce);

  return header;
}

}  // namespace rlp

}  // namespace silkworm
