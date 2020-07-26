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

#include "protocol_param.hpp"

namespace silkworm {

TEST_CASE("Execution validation") {
  using Catch::Message;

  BlockChain chain{nullptr};
  Block block{};
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
  ExecutionProcessor processor{chain, block, state};

  CHECK_THROWS_MATCHES(processor.execute_transaction(txn), ValidationError,
                       Message("missing sender"));

  // sender is still not in the state
  txn.from = 0x68d7899b6635146a37d01934461d0c9e4b65ddda_address;
  CHECK_THROWS_MATCHES(processor.execute_transaction(txn), ValidationError,
                       Message("missing sender"));

  // TODO(Andrew) other validation errors
}

TEST_CASE("No refund on error") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 10'050'107;
  block.header.gas_limit = 328'646;
  block.header.beneficiary = 0x5146556427ff689250ed1801a783d12138c3dd5e_address;
  evmc::address caller{0x834e9b529ac9fa63b39a06f8d8c9b0d6791fa5df_address};
  uint64_t nonce{3};

  // This contract initially sets its 0th storage to 0x2a.
  // When called, it updates the 0th storage to the input provided.
  Bytes code{from_hex("602a60005560098060106000396000f36000358060005531")};
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
  ExecutionProcessor processor{chain, block, state};

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

  Receipt receipt1{processor.execute_transaction(txn)};
  CHECK(std::get<bool>(receipt1.post_state_or_status));

  // Call the newly created contract
  txn.nonce = nonce + 1;
  txn.to = create_address(caller, nonce);

  // It should run SSTORE(0,0) with a potential refund
  txn.data.clear();

  // But then there's not enough gas for the BALANCE operation
  txn.gas_limit = fee::kGTransaction + 5'020;

  Receipt receipt2{processor.execute_transaction(txn)};
  CHECK(!std::get<bool>(receipt2.post_state_or_status));
  CHECK(receipt2.cumulative_gas_used - receipt1.cumulative_gas_used == txn.gas_limit);
}

TEST_CASE("Self-destruct") {
  BlockChain chain{nullptr};
  Block block{};
  block.header.number = 1'487'375;
  block.header.gas_limit = 4'712'388;
  block.header.beneficiary = 0x61c808d82a3ac53231750dadc13c777b59310bd9_address;
  evmc::address suicidal_address{0x6d20c1c07e56b7098eb8c50ee03ba0f6f498a91d_address};
  evmc::address caller_address{0x4bf2054ffae7a454a35fd8cf4be21b23b1f25a6f_address};

  // The contract self-destructs if called with zero value.
  Bytes suicidal_code{from_hex("346007576000ff5b")};
  /* https://github.com/CoinCulture/evm-tools
  0      CALLVALUE
  1      PUSH1  => 07
  3      JUMPI
  4      PUSH1  => 00
  6      SUICIDE
  7      JUMPDEST
  */

  // The caller calls the input contract three times:
  // twice with zero value and once with non-zero value.
  Bytes caller_code{
      from_hex("600080808080803561eeeef150600080808080803561eeeef15060008080806005813561eeeef1")};
  /* https://github.com/CoinCulture/evm-tools
  0      PUSH1  => 00
  2      DUP1
  3      DUP1
  4      DUP1
  5      DUP1
  6      DUP1
  7      CALLDATALOAD
  8      PUSH2  => eeee
  11     CALL
  12     POP
  13     PUSH1  => 00
  15     DUP1
  16     DUP1
  17     DUP1
  18     DUP1
  19     DUP1
  20     CALLDATALOAD
  21     PUSH2  => eeee
  24     CALL
  25     POP
  26     PUSH1  => 00
  28     DUP1
  29     DUP1
  30     DUP1
  31     PUSH1  => 05
  33     DUP2
  34     CALLDATALOAD
  35     PUSH2  => eeee
  38     CALL
  */

  IntraBlockState state{nullptr};
  ExecutionProcessor processor{chain, block, state};

  state.add_to_balance(caller_address, kEther);
  state.set_code(caller_address, caller_code);
  state.set_code(suicidal_address, suicidal_code);

  Transaction txn{
      .nonce = 0,
      .gas_price = 20 * kGiga,
      .gas_limit = 100'000,
      .to = caller_address,
      .value = 0,
  };
  txn.from = caller_address;

  evmc::bytes32 address_as_hash{to_hash(full_view(suicidal_address))};
  txn.data = full_view(address_as_hash);

  Receipt receipt1{processor.execute_transaction(txn)};
  CHECK(std::get<bool>(receipt1.post_state_or_status));

  CHECK(!state.exists(suicidal_address));

  // Now the contract is self-destructed, this is a simple value transfer
  txn.nonce = 1;
  txn.to = suicidal_address;
  txn.data.clear();

  Receipt receipt2{processor.execute_transaction(txn)};
  CHECK(std::get<bool>(receipt2.post_state_or_status));

  CHECK(state.exists(suicidal_address));
  CHECK(state.get_balance(suicidal_address) == 0);

  CHECK(receipt2.cumulative_gas_used == receipt1.cumulative_gas_used + fee::kGTransaction);
}
}  // namespace silkworm
