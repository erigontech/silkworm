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

#include "evm.hpp"

#include "../tests/catch.hpp"

namespace silkworm::eth {

TEST_CASE("value transfer", "[evm]") {
  uint64_t block_number{10336006};
  evmc::address miner{0x4c549990a7ef3fea8784406c1eecc98bf4211fa5_address};
  evmc::address from{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
  evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};
  intx::uint256 value{10'200'000'000'000'000};

  IntraBlockState state;
  EVM evm{state, miner, block_number};

  CHECK(state.get_balance(from) == 0);
  CHECK(state.get_balance(to) == 0);

  CallResult res = evm.call(from, to, "", 0, value);
  CHECK(res.status == static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW));

  state.add_to_balance(from, kEther);

  res = evm.call(from, to, "", 0, value);
  CHECK(res.status == EVMC_SUCCESS);

  CHECK(state.get_balance(from) == kEther - value);
  CHECK(state.get_balance(to) == value);
}

}  // namespace silkworm::eth
