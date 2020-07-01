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

#ifndef SILKWORM_ETH_BLOCK_H_
#define SILKWORM_ETH_BLOCK_H_

#include <stdint.h>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <string_view>
#include <vector>

#include "bloom.hpp"
#include "common.hpp"
#include "rlp/decode.hpp"
#include "transaction.hpp"

namespace silkworm::eth {

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

  std::string_view extra_data() const {
    return {byte_pointer_cast(extra_data_.bytes), extra_data_size_};
  }

  evmc::bytes32 mix_hash;
  uint8_t nonce[8]{0};

 private:
  friend void rlp::decode<BlockHeader>(std::istream& from, BlockHeader& to);

  evmc::bytes32 extra_data_;
  uint32_t extra_data_size_{0};
};

struct Block {
  BlockHeader header;
  std::vector<BlockHeader> ommers;
  std::vector<Transaction> transactions;
};

namespace rlp {

template <>
void decode(std::istream& from, BlockHeader& to);
}  // namespace rlp
}  // namespace silkworm::eth

#endif  // SILKWORM_ETH_BLOCK_H_
