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

#include "processor.hpp"

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

#include "config/protocol_param.hpp"

namespace silkworm {

TEST_CASE("Execution validation") {
  Block block;
  block.header.number = 1;
  block.header.beneficiary = 0x829bd824b016326a401d083b33d092293333a830_address;

  Transaction txn{
      .nonce = 12,
      .gas_price = 20 * kGiga,
      .gas_limit = fee::kGTransaction,
      .to = 0x727fc6a68321b754475c668a6abfb6e9e71c169a_address,
      .value = 10 * kEther,
  };

  IntraBlockState state{nullptr};
  ExecutionProcessor processor{state, block};

  ExecutionResult res{processor.execute_transaction(txn)};
  CHECK(res.error == ValidationError::kMissingSender);

  txn.from = 0x68d7899b6635146a37d01934461d0c9e4b65ddda_address;
  res = processor.execute_transaction(txn);
  CHECK(res.error == ValidationError::kMissingSender);

  // TODO(Andrew) other validation errors
}

TEST_CASE("No refund on error") {
  using boost::algorithm::unhex;
  using namespace std::string_literals;

  Block block{};
  block.header.number = 10'050'107;
  block.header.gas_limit = 328'646;
  block.header.beneficiary = 0x5146556427ff689250ed1801a783d12138c3dd5e_address;
  evmc::address caller{0x834e9b529ac9fa63b39a06f8d8c9b0d6791fa5df_address};
  uint64_t nonce{3};

  // This contract initially sets its 0th storage to 0x2a.
  // When called, it updates the 0th storage to the input provided.
  std::string code = unhex("602a60005560098060106000396000f36000358060005531"s);
  /* https://github.com/CoinCulture/evm-tools
  0      PUSH1  => 2a
  2      PUSH1  => 00
  4      SSTORE
  5      PUSH1  => 09
  7      DUP1
  8      PUSH1  => 10
  10     PUSH1  => 00
  12     CODECOPY
  13     PUSH1  => 00
  15     RETURN
-----------------------------
  16     PUSH1  => 00
  18     CALLDATALOAD
  19     DUP1
  20     PUSH1  => 00
  22     SSTORE
  23     BALANCE
  */

  IntraBlockState state{nullptr};
  ExecutionProcessor processor{state, block};

  Transaction txn{
      .nonce = nonce,
      .gas_price = 59 * kGiga,
      .gas_limit = 103'858,
      .to = {},
      .value = 0,
      .data = code,
  };

  state.add_to_balance(caller, kEther);
  state.set_nonce(caller, nonce);
  txn.from = caller;

  ExecutionResult res{processor.execute_transaction(txn)};
  CHECK(res.error == ValidationError::kOk);
  CHECK(std::get<bool>(res.receipt.post_state_or_status));

  // Call the newly created contract
  txn.nonce = nonce + 1;
  txn.to = create_address(caller, nonce);

  // It should run SSTORE(0,0) with a potential refund
  txn.data.clear();

  // But then there's not enough gas for the BALANCE operation
  txn.gas_limit = fee::kGTransaction + 5'020;

  res = processor.execute_transaction(txn);
  CHECK(res.error == ValidationError::kOk);
  CHECK(!std::get<bool>(res.receipt.post_state_or_status));
  CHECK(res.gas_used == txn.gas_limit);
}
}  // namespace silkworm
