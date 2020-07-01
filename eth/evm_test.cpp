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

#include <boost/algorithm/hex.hpp>
#include <catch2/catch.hpp>
#include <string>

#include "protocol_param.hpp"

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

TEST_CASE("smart contract", "[evm]") {
  using boost::algorithm::unhex;
  using namespace std::string_literals;

  uint64_t block_number{10336006};
  evmc::address miner{0x4c549990a7ef3fea8784406c1eecc98bf4211fa5_address};
  evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

  // This contract initially sets its 0th storage to 0x2a
  // and its 1st storage to 0x01c9.
  // When called, it updates the 0th storage to the input provided.
  std::string code = unhex("602a6000556101c960015560068060166000396000f3600035600055"s);
  // https://github.com/CoinCulture/evm-tools
  // 0      PUSH1  => 2a
  // 2      PUSH1  => 00
  // 4      SSTORE         // storage[0] = 0x2a
  // 5      PUSH2  => 01c9
  // 8      PUSH1  => 01
  // 10     SSTORE         // storage[1] = 0x01c9
  // 11     PUSH1  => 06   // deploy begin
  // 13     DUP1
  // 14     PUSH1  => 16
  // 16     PUSH1  => 00
  // 18     CODECOPY
  // 19     PUSH1  => 00
  // 21     RETURN         // deploy end
  // 22     PUSH1  => 00   // contract code
  // 24     CALLDATALOAD
  // 25     PUSH1  => 00
  // 27     SSTORE         // storage[0] = input[0]

  IntraBlockState state;
  EVM evm{state, miner, block_number};

  uint64_t gas{0};
  CallResult res = evm.create(caller, code, gas, 0);
  CHECK(res.status == EVMC_OUT_OF_GAS);

  gas = 50'000;
  res = evm.create(caller, code, gas, 0);
  CHECK(res.status == EVMC_SUCCESS);

  evmc::address contract_address = create_address(caller, 0);
  evmc::bytes32 key0;
  CHECK(state.get_storage(contract_address, key0) == bytes_to_hash("\x2a"));

  evmc::bytes32 new_val{bytes_to_hash("\xf5")};
  res = evm.call(caller, contract_address, hash_to_string_view(new_val), gas, 0);
  CHECK(res.status == EVMC_SUCCESS);
  CHECK(state.get_storage(contract_address, key0) == new_val);
}

}  // namespace silkworm::eth
