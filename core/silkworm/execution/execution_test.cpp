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

#include "execution.hpp"

#include <cstring>

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/state/in_memory_state.hpp>
#include <silkworm/trie/vector_root.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

TEST_CASE("Execute two blocks") {
    // ---------------------------------------
    // Prepare
    // ---------------------------------------

    uint64_t block_number{1};
    auto miner{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};

    Block block{};
    block.header.number = block_number;
    block.header.beneficiary = miner;
    block.header.gas_limit = 100'000;
    block.header.gas_used = 98'824;

    static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
    std::vector<Receipt> receipts{
        {Transaction::Type::kEip1559, true, block.header.gas_used, {}, {}},
    };
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates its 0th storage to the input provided.
    Bytes contract_code{*from_hex("600035600055")};
    Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].type = Transaction::Type::kEip1559;
    block.transactions[0].max_priority_fee_per_gas = 0;
    block.transactions[0].max_fee_per_gas = 20 * kGiga;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].from = sender;

    InMemoryState state;
    Account sender_account{};
    sender_account.balance = kEther;
    state.update_account(sender, std::nullopt, sender_account);

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------

    REQUIRE(execute_block(block, state, test::kLondonConfig) == ValidationResult::kOk);

    auto contract_address{create_address(sender, /*nonce=*/0)};
    std::optional<Account> contract_account{state.read_account(contract_address)};
    REQUIRE(contract_account != std::nullopt);

    ethash::hash256 code_hash{keccak256(contract_code)};
    CHECK(to_hex(contract_account->code_hash) == to_hex(code_hash.bytes));

    evmc::bytes32 storage_key0{};
    evmc::bytes32 storage0{state.read_storage(contract_address, kDefaultIncarnation, storage_key0)};
    CHECK(to_hex(storage0) == "000000000000000000000000000000000000000000000000000000000000002a");

    evmc::bytes32 storage_key1{to_bytes32(*from_hex("01"))};
    evmc::bytes32 storage1{state.read_storage(contract_address, kDefaultIncarnation, storage_key1)};
    CHECK(to_hex(storage1) == "00000000000000000000000000000000000000000000000000000000000001c9");

    std::optional<Account> miner_account{state.read_account(miner)};
    REQUIRE(miner_account);
    CHECK(miner_account->balance == param::kBlockRewardConstantinople);

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------

    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block_number = 2;
    block.header.number = block_number;
    block.header.gas_used = 26'149;
    receipts[0].cumulative_gas_used = block.header.gas_used;
    block.header.receipts_root = trie::root_hash(receipts, kEncoder);

    block.transactions[0].nonce = 1;
    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    REQUIRE(execute_block(block, state, test::kLondonConfig) == ValidationResult::kOk);

    storage0 = state.read_storage(contract_address, kDefaultIncarnation, storage_key0);
    CHECK(to_hex(storage0) == new_val);

    miner_account = state.read_account(miner);
    REQUIRE(miner_account != std::nullopt);
    CHECK(miner_account->balance > 2 * param::kBlockRewardConstantinople);
    CHECK(miner_account->balance < 3 * param::kBlockRewardConstantinople);
}
}  // namespace silkworm
