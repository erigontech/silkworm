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

#ifndef SILKWORM_ETH_TRANSACTION_H_
#define SILKWORM_ETH_TRANSACTION_H_

#include <stdint.h>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <istream>
#include <optional>
#include <ostream>
#include <string>

#include "../rlp/decode.hpp"

namespace silkworm {

namespace eth {

struct Transaction {
  uint64_t nonce{0};
  intx::uint256 gas_price;
  uint64_t gas_limit{0};
  std::optional<evmc::address> to;
  intx::uint256 value;
  std::string data;
  intx::uint256 v, r, s;              // signature
  std::optional<evmc::address> from;  // sender recovered from the signature
};

bool operator==(const Transaction& a, const Transaction& b);

}  // namespace eth

namespace rlp {
void encode(std::ostream& to, const eth::Transaction& txn);

template <>
void decode(std::istream& from, eth::Transaction& to);
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_ETH_TRANSACTION_H_
