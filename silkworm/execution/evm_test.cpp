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

#include <catch2/catch.hpp>

#include "protocol_param.hpp"

namespace silkworm {

TEST_CASE("Value transfer") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 10336006;
  block.header.beneficiary = 0x4c549990a7ef3fea8784406c1eecc98bf4211fa5_address;

  evmc::address from{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
  evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};
  intx::uint256 value{10'200'000'000'000'000};

  IntraBlockState state{nullptr};
  EVM evm{chain, block, state};

  CHECK(state.get_balance(from) == 0);
  CHECK(state.get_balance(to) == 0);

  Transaction txn{};
  txn.from = from;
  txn.to = to;
  txn.value = value;

  CallResult res{evm.execute(txn, 0)};
  CHECK(res.status == static_cast<evmc_status_code>(EVMC_BALANCE_TOO_LOW));

  state.add_to_balance(from, kEther);

  res = evm.execute(txn, 0);
  CHECK(res.status == EVMC_SUCCESS);

  CHECK(state.get_balance(from) == kEther - value);
  CHECK(state.get_balance(to) == value);
}

TEST_CASE("Smart contract with storage") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 10'336'006;
  block.header.beneficiary = 0x4c549990a7ef3fea8784406c1eecc98bf4211fa5_address;
  evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

  // This contract initially sets its 0th storage to 0x2a
  // and its 1st storage to 0x01c9.
  // When called, it updates the 0th storage to the input provided.
  Bytes code{from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
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

  IntraBlockState state{nullptr};
  EVM evm{chain, block, state};

  Transaction txn{};
  txn.from = caller;
  txn.data = code;

  uint64_t gas{0};
  CallResult res{evm.execute(txn, gas)};
  CHECK(res.status == EVMC_OUT_OF_GAS);

  gas = 50'000;
  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_SUCCESS);

  evmc::address contract_address{create_address(caller, /*nonce=*/1)};
  evmc::bytes32 key0{};
  CHECK(to_hex(zeroless_view(state.get_storage(contract_address, key0))) == "2a");

  evmc::bytes32 new_val{to_hash(from_hex("f5"))};
  txn.to = contract_address;
  txn.data = full_view(new_val);

  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_SUCCESS);
  CHECK(state.get_storage(contract_address, key0) == new_val);
}

TEST_CASE("Double self-destruct") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 116'525;
  block.header.beneficiary = 0xe6a7a1d47ff21b6321162aea7c6cb457d5476bca_address;
  evmc::address caller{0xc876c021ece519a8cb7d3d1b8eea2d1cee9929ba_address};

  // This contract initially sets its 0th storage to 0x2a.
  // When called, it updates the 0th storage to the input provided
  // an then self-destructs.
  Bytes code{from_hex("602a60005560088060106000396000f360003580600055ff")};
  /* https://github.com/CoinCulture/evm-tools
  0      PUSH1  => 2a
  2      PUSH1  => 00
  4      SSTORE
  5      PUSH1  => 08
  7      DUP1
  8      PUSH1  => 10
  10     PUSH1  => 00
  12     CODECOPY
  13     PUSH1  => 00
  15     RETURN
---------------------------
  16     PUSH1  => 00
  18     CALLDATALOAD
  19     DUP1
  20     PUSH1  => 00
  22     SSTORE
  23     SUICIDE
  */

  IntraBlockState state{nullptr};
  EVM evm{chain, block, state};

  Transaction txn{};
  txn.from = caller;
  txn.data = code;

  uint64_t gas{1'000'000};
  CallResult res{evm.execute(txn, gas)};
  CHECK(res.status == EVMC_SUCCESS);

  evmc::address contract_address{create_address(caller, /*nonce=*/0)};
  evmc::bytes32 key0{};
  CHECK(to_hex(zeroless_view(state.get_storage(contract_address, key0))) == "2a");

  // Call the contract so that it self-destructs
  evmc::bytes32 new_val{to_hash(from_hex("f5"))};
  txn.to = contract_address;
  txn.data = full_view(new_val);

  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_SUCCESS);
  CHECK(state.get_storage(contract_address, key0) == evmc::bytes32{});
  CHECK(res.gas_left < gas);

  // Now the contract is self-destructed, this is a simple value transfer
  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_SUCCESS);
  CHECK(state.get_storage(contract_address, key0) == evmc::bytes32{});
  CHECK(res.gas_left == gas);
}

TEST_CASE("Maximum call depth") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 1'431'916;
  evmc::address caller{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
  evmc::address contract{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

  // The contract just calls itself recursively a given number of times.
  Bytes code{from_hex("60003580600857005b6001900360005260008060208180305a6103009003f1602357fe5b")};
  /* https://github.com/CoinCulture/evm-tools
  0      PUSH1  => 00
  2      CALLDATALOAD
  3      DUP1
  4      PUSH1  => 08
  6      JUMPI
  7      STOP
  8      JUMPDEST
  9      PUSH1  => 01
  11     SWAP1
  12     SUB
  13     PUSH1  => 00
  15     MSTORE
  16     PUSH1  => 00
  18     DUP1
  19     PUSH1  => 20
  21     DUP2
  22     DUP1
  23     ADDRESS
  24     GAS
  25     PUSH2  => 0300
  28     SWAP1
  29     SUB
  30     CALL
  31     PUSH1  => 23
  33     JUMPI
  34     INVALID
  35     JUMPDEST
  */

  IntraBlockState state{nullptr};
  state.set_code(contract, code);

  EVM evm{chain, block, state};

  Transaction txn{};
  txn.from = caller;
  txn.to = contract;

  uint64_t gas{1'000'000};
  CallResult res{evm.execute(txn, gas)};
  CHECK(res.status == EVMC_SUCCESS);

  evmc::bytes32 num_of_recursions{to_hash(from_hex("0400"))};
  txn.data = full_view(num_of_recursions);
  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_SUCCESS);

  num_of_recursions = to_hash(from_hex("0401"));
  txn.data = full_view(num_of_recursions);
  res = evm.execute(txn, gas);
  CHECK(res.status == EVMC_INVALID_INSTRUCTION);
}

TEST_CASE("Create address") {
  CHECK(create_address(0xfbe0afcd7658ba86be41922059dd879c192d4c73_address, 0) ==
        0xc669eaad75042be84daaf9b461b0e868b9ac1871_address);
}
}  // namespace silkworm
