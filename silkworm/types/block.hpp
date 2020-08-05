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

#ifndef SILKWORM_TYPES_BLOCK_H_
#define SILKWORM_TYPES_BLOCK_H_

#include <stdint.h>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/decode.hpp>
#include <silkworm/types/bloom.hpp>
#include <silkworm/types/transaction.hpp>
#include <vector>

namespace silkworm {

struct BlockHeader {
  evmc::bytes32 parent_hash;
  evmc::bytes32 ommers_hash;
  evmc::address beneficiary;
  evmc::bytes32 state_root;
  evmc::bytes32 transactions_root;
  evmc::bytes32 receipts_root;
  Bloom logs_bloom;
  intx::uint256 difficulty;
  uint64_t number{0};
  uint64_t gas_limit{0};
  uint64_t gas_used{0};
  uint64_t timestamp{0};

  ByteView extra_data() const { return {extra_data_.bytes, extra_data_size_}; }

  evmc::bytes32 mix_hash;
  uint8_t nonce[8]{0};

 private:
  friend void rlp::decode<BlockHeader>(ByteView& from, BlockHeader& to);

  evmc::bytes32 extra_data_;
  uint32_t extra_data_size_{0};
};

struct BlockBody {
  std::vector<Transaction> transactions;
  std::vector<BlockHeader> ommers;
};

struct Block : public BlockBody {
  BlockHeader header;
};

struct BlockWithHash {
  Block block;
  evmc::bytes32 hash;
};

namespace rlp {

template <>
void decode(ByteView& from, BlockBody& to);

template <>
void decode(ByteView& from, BlockHeader& to);
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_TYPES_BLOCK_H_
