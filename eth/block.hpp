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
#include <string>

#include "../rlp/decode.hpp"
#include "bloom.hpp"

namespace silkworm {

namespace eth {

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
  std::string extra_data;  // TODO(Andrew) evmc::bytes32 to protect against large lengths
  evmc::bytes32 mix_hash;
  uint8_t nonce[8]{0};
};

}  // namespace eth

namespace rlp {
void encode(std::ostream& to, const eth::BlockHeader& header);

template <>
eth::BlockHeader decode(std::istream& from);
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_ETH_BLOCK_H_
