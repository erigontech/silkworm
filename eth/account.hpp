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

#ifndef SILKWORM_ETH_ACCOUNT_H_
#define SILKWORM_ETH_ACCOUNT_H_

#include <intx/intx.hpp>
#include <istream>
#include <ostream>

#include "../rlp/decode.hpp"
#include "common.hpp"

namespace silkworm {

namespace eth {

struct Account {
  uint64_t nonce{0};
  intx::uint256 balance;
  evmc::bytes32 storage_root{kEmptyRoot};
  evmc::bytes32 code_hash{kEmptyHash};
  uint64_t incarnation{0};
};

bool operator==(const Account& a, const Account& b);

}  // namespace eth

namespace rlp {
void encode(std::ostream& to, const eth::Account& account);

template <>
eth::Account decode(std::istream& from);
}  // namespace rlp
}  // namespace silkworm

#endif  // SILKWORM_ETH_ACCOUNT_H_
