/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/state/memory_buffer.hpp>

#include "address.hpp"

namespace silkworm {

TEST_CASE("Value transfer") {
    Block block{};
    block.header.number = 10336006;

    evmc::address from{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};
    evmc::address to{0x8b299e2b7d7f43c0ce3068263545309ff4ffb521_address};
    intx::uint256 value{10'200'000'000'000'000};

    MemoryBuffer db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    CHECK(state.get_balance(from) == 0);
    CHECK(state.get_balance(to) == 0);

    Transaction txn{};
    txn.from = from;
    txn.to = to;
    txn.value = value;

    CallResult res{evm.execute(txn, 0)};
    CHECK(res.status == EVMC_INSUFFICIENT_BALANCE);
    CHECK(res.data == Bytes{});

    state.add_to_balance(from, kEther);

    res = evm.execute(txn, 0);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});

    CHECK(state.get_balance(from) == kEther - value);
    CHECK(state.get_balance(to) == value);
}

TEST_CASE("Smart contract with storage") {
    Block block{};
    block.header.number = 10'336'006;
    evmc::address caller{0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address};

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates the 0th storage to the input provided.
    Bytes code{*from_hex("602a6000556101c960015560068060166000396000f3600035600055")};
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

    MemoryBuffer db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas{0};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_OUT_OF_GAS);
    CHECK(res.data == Bytes{});

    gas = 50'000;
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == silkworm::from_hex("600035600055"));

    evmc::address contract_address{create_address(caller, /*nonce=*/1)};
    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(contract_address, key0))) == "2a");

    evmc::bytes32 new_val{to_bytes32(*from_hex("f5"))};
    txn.to = contract_address;
    txn.data = full_view(new_val);

    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});
    CHECK(state.get_current_storage(contract_address, key0) == new_val);
}

TEST_CASE("Maximum call depth") {
    Block block{};
    block.header.number = 1'431'916;
    evmc::address caller{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address contract{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The contract just calls itself recursively a given number of times.
    Bytes code{*from_hex("60003580600857005b6001900360005260008060208180305a6103009003f1602357fe5b")};
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

    MemoryBuffer db;
    IntraBlockState state{db};
    state.set_code(contract, code);

    EVM evm{block, state, kMainnetConfig};

    AnalysisCache analysis_cache{/*maxSize=*/16};
    evm.advanced_analysis_cache = &analysis_cache;

    Transaction txn{};
    txn.from = caller;
    txn.to = contract;

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});

    evmc::bytes32 num_of_recursions{to_bytes32(*from_hex("0400"))};
    txn.data = full_view(num_of_recursions);
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});

    num_of_recursions = to_bytes32(*from_hex("0401"));
    txn.data = full_view(num_of_recursions);
    res = evm.execute(txn, gas);
    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.data == Bytes{});
}

TEST_CASE("DELEGATECALL") {
    Block block{};
    block.header.number = 1'639'560;
    evmc::address caller_address{0x8e4d1ea201b908ab5e1f5a1c3f9f1b4f6c1e9cf1_address};
    evmc::address callee_address{0x3589d05a1ec4af9f65b0e5554e645707775ee43c_address};

    // The callee writes the ADDRESS to storage.
    Bytes callee_code{*from_hex("30600055")};
    /* https://github.com/CoinCulture/evm-tools
    0      ADDRESS
    1      PUSH1  => 00
    3      SSTORE
    */

    // The caller delegate-calls the input contract.
    Bytes caller_code{*from_hex("6000808080803561eeeef4")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 00
    2      DUP1
    3      DUP1
    4      DUP1
    5      DUP1
    6      CALLDATALOAD
    7      PUSH2  => eeee
    10     DELEGATECALL
    */

    MemoryBuffer db;
    IntraBlockState state{db};
    state.set_code(caller_address, caller_code);
    state.set_code(callee_address, callee_code);

    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller_address;
    txn.to = caller_address;
    txn.data = full_view(to_bytes32(full_view(callee_address)));

    uint64_t gas{1'000'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});

    evmc::bytes32 key0{};
    CHECK(to_hex(zeroless_view(state.get_current_storage(caller_address, key0))) == to_hex(full_view(caller_address)));
}

// https://eips.ethereum.org/EIPS/eip-211#specification
TEST_CASE("CREATE should only return on failure") {
    Block block{};
    block.header.number = 4'575'910;
    evmc::address caller{0xf466859ead1932d743d622cb74fc058882e8648a_address};

    Bytes code{
        *from_hex("0x602180601360003960006000f0503d600055006211223360005260206000602060006000600461900"
                  "0f1503d60005560206000f3")};
    /* https://github.com/CoinCulture/evm-tools
    0      PUSH1  => 21
    2      DUP1
    3      PUSH1  => 13
    5      PUSH1  => 00
    7      CODECOPY
    8      PUSH1  => 00
    10     PUSH1  => 00
    12     CREATE
    13     POP
    14     RETURNDATASIZE
    15     PUSH1  => 00
    17     SSTORE
    18     STOP
    19     PUSH3  => 112233
    23     PUSH1  => 00
    25     MSTORE
    26     PUSH1  => 20
    28     PUSH1  => 00
    30     PUSH1  => 20
    32     PUSH1  => 00
    34     PUSH1  => 00
    36     PUSH1  => 04
    38     PUSH2  => 9000
    41     CALL
    42     POP
    43     RETURNDATASIZE
    44     PUSH1  => 00
    46     SSTORE
    47     PUSH1  => 20
    49     PUSH1  => 00
    51     RETURN
    */

    MemoryBuffer db;
    IntraBlockState state{db};
    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = code;

    uint64_t gas{150'000};
    CallResult res{evm.execute(txn, gas)};
    CHECK(res.status == EVMC_SUCCESS);
    CHECK(res.data == Bytes{});

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};
    evmc::bytes32 key0{};
    CHECK(is_zero(state.get_current_storage(contract_address, key0)));
}

// https://github.com/ethereum/EIPs/issues/684
TEST_CASE("Contract overwrite") {
    Block block{};
    block.header.number = 7'753'545;

    Bytes old_code{*from_hex("6000")};
    Bytes new_code{*from_hex("6001")};

    evmc::address caller{0x92a1d964b8fc79c5694343cc943c27a94a3be131_address};

    evmc::address contract_address{create_address(caller, /*nonce=*/0)};

    MemoryBuffer db;
    IntraBlockState state{db};
    state.set_code(contract_address, old_code);

    EVM evm{block, state, kMainnetConfig};

    Transaction txn{};
    txn.from = caller;
    txn.data = new_code;

    uint64_t gas{100'000};
    CallResult res{evm.execute(txn, gas)};

    CHECK(res.status == EVMC_INVALID_INSTRUCTION);
    CHECK(res.gas_left == 0);
    CHECK(res.data == Bytes{});
}

TEST_CASE("EIP-3541: Reject new contracts starting with the 0xEF byte") {
    ChainConfig config{kMainnetConfig};
    config.set_revision_block(EVMC_LONDON, 13'000'000);

    Block block;
    block.header.number = 13'500'000;

    MemoryBuffer db;
    IntraBlockState state{db};
    EVM evm{block, state, config};

    Transaction txn;
    txn.from = 0x1000000000000000000000000000000000000000_address;
    const uint64_t gas{50'000};

    // https://eips.ethereum.org/EIPS/eip-3541#test-cases
    txn.data = *from_hex("0x60ef60005360016000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360026000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360036000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60ef60005360206000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_CONTRACT_VALIDATION_FAILURE);

    txn.data = *from_hex("0x60fe60005360016000f3");
    CHECK(evm.execute(txn, gas).status == EVMC_SUCCESS);
}

}  // namespace silkworm
