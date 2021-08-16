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

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>

#include <iostream>
#include <silkworm/common/cast.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/chain/config.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

#include "stagedsync.hpp"

using namespace evmc::literals;

TEST_CASE("Stage History indexs (Account + Storage)") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    // ---------------------------------------
    // Prepare
    // ---------------------------------------

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
    Bytes contract_code{*from_hex("600035600055")};
    Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].max_priority_fee_per_gas = 0;  // EIP-1559
    block.transactions[0].max_fee_per_gas = 20 * kGiga;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].from = sender;

    db::Buffer buffer{*txn};
    Account sender_account{};
    sender_account.balance = kEther;
    buffer.update_account(sender, std::nullopt, sender_account);

    std::vector<Receipt> receipts;

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------
    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);
    auto contract_address{create_address(sender, /*nonce=*/0)};

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------

    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block_number = 2;
    block.header.number = block_number;
    block.header.gas_used = 26'201;

    block.transactions[0].nonce = 1;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);

    // ---------------------------------------
    // Execute third block
    // ---------------------------------------

    new_val = "000000000000000000000000000000000000000000000000000000000000003b";

    block_number = 3;
    block.header.number = block_number;
    block.header.gas_used = 26'201;

    block.transactions[0].nonce = 2;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);
    buffer.write_to_db();
    db::stages::set_stage_progress(*txn, db::stages::kExecutionKey, 3);

    CHECK(stagedsync::stage_account_history(txn, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);
    CHECK(stagedsync::stage_storage_history(txn, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);

    auto account_history_table{db::open_cursor(*txn, db::table::kAccountHistory)};
    auto storage_history_table{db::open_cursor(*txn, db::table::kStorageHistory)};
    // Account retrieving from Databse
    auto bitmap_address_sender_bytes{account_history_table.lower_bound(db::to_slice(sender)).value};
    auto bitmap_address_contract_bytes{account_history_table.lower_bound(db::to_slice(contract_address)).value};
    // Bitmaps computation of accounts
    auto bitmap_address_sender{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_address_sender_bytes).data()), bitmap_address_sender_bytes.size())};
    auto bitmap_address_contract{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_address_contract_bytes).data()), bitmap_address_contract_bytes.size())};
    // Checks on account's bitmaps
    CHECK(bitmap_address_sender.cardinality() == 3);
    CHECK(bitmap_address_contract.cardinality() == 3);
    CHECK(bitmap_address_sender.toString() == "{1,2,3}");
    CHECK(bitmap_address_contract.toString() == "{1,2,3}");
    // The location is the first so it's at 0
    evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
    // Composite: Address + Location
    Bytes composite(kAddressLength + kHashLength, '\0');
    std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
    std::memcpy(&composite[kHashLength], location.bytes, kHashLength);
    // Storage retrieving from Databse
    auto bitmap_storage_contract_bytes{storage_history_table.lower_bound(db::to_slice(composite)).value};
    // Bitmaps computing for storage
    auto bitmap_storage_contract{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_storage_contract_bytes).data()), bitmap_storage_contract_bytes.size())};
    // Checks on storage's bitmaps
    CHECK(bitmap_storage_contract.cardinality() == 2);
    CHECK(bitmap_storage_contract.toString() == "{2,3}");
}

TEST_CASE("Unwind History indexs (Account + Storage)") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    // ---------------------------------------
    // Prepare
    // ---------------------------------------

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
    Bytes contract_code{*from_hex("600035600055")};
    Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].max_priority_fee_per_gas = 0;  // EIP-1559
    block.transactions[0].max_fee_per_gas = 20 * kGiga;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].from = sender;

    db::Buffer buffer{*txn};
    Account sender_account{};
    sender_account.balance = kEther;
    buffer.update_account(sender, std::nullopt, sender_account);

    std::vector<Receipt> receipts;

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------
    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);
    auto contract_address{create_address(sender, /*nonce=*/0)};

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------

    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block_number = 2;
    block.header.number = block_number;
    block.header.gas_used = 26'201;

    block.transactions[0].nonce = 1;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);

    // ---------------------------------------
    // Execute third block
    // ---------------------------------------

    new_val = "000000000000000000000000000000000000000000000000000000000000003b";

    block_number = 3;
    block.header.number = block_number;
    block.header.gas_used = 26'201;

    block.transactions[0].nonce = 2;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    CHECK(execute_block(block, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);
    buffer.write_to_db();
    db::stages::set_stage_progress(*txn, db::stages::kExecutionKey, 3);

    CHECK(stagedsync::stage_account_history(txn, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);
    CHECK(stagedsync::stage_storage_history(txn, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);
    CHECK(stagedsync::unwind_account_history(txn, data_dir.get_etl_path(), 2) == stagedsync::StageResult::kSuccess);
    CHECK(stagedsync::unwind_storage_history(txn, data_dir.get_etl_path(), 2) == stagedsync::StageResult::kSuccess);

    auto account_history_table{db::open_cursor(*txn, db::table::kAccountHistory)};
    auto storage_history_table{db::open_cursor(*txn, db::table::kStorageHistory)};
    // Account retrieving from Databse
    auto bitmap_address_sender_bytes{account_history_table.lower_bound(db::to_slice(sender)).value};
    auto bitmap_address_contract_bytes{account_history_table.lower_bound(db::to_slice(contract_address)).value};
    // Bitmaps computation of accounts
    auto bitmap_address_sender{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_address_sender_bytes).data()), bitmap_address_sender_bytes.size())};
    auto bitmap_address_contract{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_address_contract_bytes).data()), bitmap_address_contract_bytes.size())};
    // Checks on account's bitmaps
    CHECK(bitmap_address_sender.cardinality() == 2);
    CHECK(bitmap_address_contract.cardinality() == 2);
    CHECK(bitmap_address_sender.toString() == "{1,2}");
    CHECK(bitmap_address_contract.toString() == "{1,2}");
    // The location is the first so it's at 0
    evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
    // Composite: Address + Location
    Bytes composite(kAddressLength + kHashLength, '\0');
    std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
    std::memcpy(&composite[kHashLength], location.bytes, kHashLength);
    // Storage retrieving from Databse
    auto bitmap_storage_contract_bytes{storage_history_table.lower_bound(db::to_slice(composite)).value};
    // Bitmaps computing for storage
    auto bitmap_storage_contract{roaring::Roaring64Map::readSafe(byte_ptr_cast(db::from_slice(bitmap_storage_contract_bytes).data()), bitmap_storage_contract_bytes.size())};
    // Checks on storage's bitmaps
    CHECK(bitmap_storage_contract.cardinality() == 1);
    CHECK(bitmap_storage_contract.toString() == "{2}");
}