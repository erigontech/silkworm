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

#include "execution.hpp"

#include <catch2/catch.hpp>
#include <cstring>
#include <ethash/keccak.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/protocol_param.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

TEST_CASE("Execution API") {
    using namespace silkworm;

    // ---------------------------------------
    // Prepare
    // ---------------------------------------

    TemporaryDirectory tmp_dir{};
    lmdb::DatabaseConfig db_config{tmp_dir.path(), 32 * kMebi};
    db_config.set_readonly(false);
    std::shared_ptr<lmdb::Environment> db_env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{db_env->begin_rw_transaction()};

    db::table::create_all(*txn);

    db::Buffer buffer{txn.get()};
    uint64_t block_number{1};

    auto miner{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};

    Block block{};
    block.header.number = block_number;
    block.header.beneficiary = miner;
    block.header.gas_limit = 100'000;
    block.header.gas_used = 63'820;

    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates its 0th storage to the input provided.
    Bytes contract_code{from_hex("600035600055")};
    Bytes deployment_code{from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].gas_price = 20 * kGiga;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].from = sender;

    Account sender_account{};
    sender_account.balance = kEther;
    auto state_table{txn->open(db::table::kPlainState)};
    state_table->put(full_view(sender), sender_account.encode_for_storage(/*omit_code_hash=*/false));

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------

    execute_block(block, buffer);

    auto contract_address{create_address(sender, /*nonce=*/0)};
    std::optional<Account> contract_account{buffer.read_account(contract_address)};
    REQUIRE(contract_account);

    ethash::hash256 code_hash{keccak256(contract_code)};
    CHECK(to_hex(contract_account->code_hash) == to_hex(full_view(code_hash.bytes)));

    uint64_t incarnation{1};

    evmc::bytes32 storage_key0{};
    evmc::bytes32 storage0{buffer.read_storage(contract_address, incarnation, storage_key0)};
    CHECK(to_hex(storage0) == "000000000000000000000000000000000000000000000000000000000000002a");

    evmc::bytes32 storage_key1{to_bytes32(from_hex("01"))};
    evmc::bytes32 storage1{buffer.read_storage(contract_address, incarnation, storage_key1)};
    CHECK(to_hex(storage1) == "00000000000000000000000000000000000000000000000000000000000001c9");

    std::optional<Account> miner_account{buffer.read_account(miner)};
    REQUIRE(miner_account);
    CHECK(miner_account->balance > 1 * param::kFrontierBlockReward);
    CHECK(miner_account->balance < 2 * param::kFrontierBlockReward);

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------

    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block_number = 2;
    block.header.number = block_number;
    block.header.gas_used = 26'201;

    block.transactions[0].nonce = 1;
    block.transactions[0].to = contract_address;
    block.transactions[0].data = from_hex(new_val);

    execute_block(block, buffer);

    storage0 = buffer.read_storage(contract_address, incarnation, storage_key0);
    CHECK(to_hex(storage0) == new_val);

    miner_account = buffer.read_account(miner);
    REQUIRE(miner_account);
    CHECK(miner_account->balance > 2 * param::kFrontierBlockReward);
    CHECK(miner_account->balance < 3 * param::kFrontierBlockReward);

    // ---------------------------------------
    // Check change sets
    // ---------------------------------------

    buffer.write_to_db();

    CHECK(buffer.account_changes().at(1) == db::read_account_changes(*txn, 1));
    CHECK(buffer.account_changes().at(2) == db::read_account_changes(*txn, 2));
    CHECK(buffer.storage_changes().at(1) == db::read_storage_changes(*txn, 1));
    CHECK(buffer.storage_changes().at(2) == db::read_storage_changes(*txn, 2));

    const db::AccountChanges& account_changes{buffer.account_changes().at(1)};
    CHECK(account_changes.size() == 3);

    // sender existed at genesis
    CHECK(!account_changes.at(sender).empty());

    // miner & contract were created in block 1
    CHECK(account_changes.at(miner).empty());
    CHECK(account_changes.at(contract_address).empty());

    db::StorageChanges storage_changes_expected{};
    storage_changes_expected[contract_address][incarnation][storage_key0] = {};
    storage_changes_expected[contract_address][incarnation][storage_key1] = {};
    CHECK(buffer.storage_changes().at(1) == storage_changes_expected);

    storage_changes_expected.clear();
    storage_changes_expected[contract_address][incarnation][storage_key0] = from_hex("2a");
    CHECK(buffer.storage_changes().at(2) == storage_changes_expected);
}
