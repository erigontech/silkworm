/*
   Copyright 2022 The Silkworm Authors

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

#include <silkworm/chain/config.hpp>
#include <silkworm/common/cast.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/db/bitmap.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/stagedsync/stage_history_index.hpp>

#include "stagedsync.hpp"

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Stage History Index") {
    test::Context context;
    db::RWTxn txn{context.txn()};

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
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;
    block.transactions[0].max_fee_per_gas = block.transactions[0].max_priority_fee_per_gas;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].r = 1;  // dummy
    block.transactions[0].s = 1;  // dummy
    block.transactions[0].from = sender;

    db::Buffer buffer{*txn, 0};
    Account sender_account{};
    sender_account.balance = kEther;
    buffer.update_account(sender, std::nullopt, sender_account);

    // ---------------------------------------
    // Execute first block
    // ---------------------------------------
    CHECK(execute_block(block, buffer, kMainnetConfig) == ValidationResult::kOk);
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

    CHECK(execute_block(block, buffer, kMainnetConfig) == ValidationResult::kOk);

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

    CHECK(execute_block(block, buffer, kMainnetConfig) == ValidationResult::kOk);
    buffer.write_to_db();
    db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, 3);

    SECTION("Forward and Unwind") {
        db::Cursor account_changes(txn, db::table::kAccountChangeSet);
        REQUIRE(!account_changes.empty());

        stagedsync::HistoryIndex stage_history_index(&context.node_settings());
        REQUIRE(stage_history_index.forward(txn) == stagedsync::StageResult::kSuccess);
        db::Cursor account_history(txn, db::table::kAccountHistory);
        db::Cursor storage_history(txn, db::table::kStorageHistory);
        REQUIRE(!account_history.empty());
        REQUIRE(!storage_history.empty());

        auto account_history_data{account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false)};
        REQUIRE(account_history_data.done);
        auto account_history_data_view{db::from_slice(account_history_data.key)};
        REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) == UINT64_MAX);
        auto account_history_bitmap{db::bitmap::from_slice(account_history_data.value)};
        REQUIRE(account_history_bitmap.cardinality() == 3);
        REQUIRE(account_history_bitmap.toString() == "{1,2,3}");

        auto storage_history_data{
            storage_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false)};
        REQUIRE(storage_history_data.done);
        auto storage_history_data_view{db::from_slice(storage_history_data.key)};
        REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) == UINT64_MAX);
        auto storage_history_bitmap{db::bitmap::from_slice(storage_history_data.value)};
        REQUIRE(storage_history_bitmap.cardinality() == 3);
        REQUIRE(storage_history_bitmap.toString() == "{1,2,3}");

        // The location is the first so it's at 0
        evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        // Composite: Address + Location
        Bytes composite(kAddressLength + kHashLength, '\0');
        std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
        std::memcpy(&composite[kAddressLength], location.bytes, kHashLength);

        // Storage retrieving from Database
        storage_history_data = storage_history.lower_bound(db::to_slice(composite), false);
        REQUIRE(storage_history_data.done);
        storage_history_data_view = db::from_slice(storage_history_data.key);
        REQUIRE(storage_history_data_view.starts_with(composite));
        REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) == UINT64_MAX);
        storage_history_bitmap = db::bitmap::from_slice(storage_history_data.value);
        REQUIRE(storage_history_bitmap.cardinality() == 3);
        REQUIRE(storage_history_bitmap.toString() == "{1,2,3}");

        REQUIRE(stage_history_index.unwind(txn, 2) == stagedsync::StageResult::kSuccess);
        REQUIRE(db::stages::read_stage_progress(*txn, db::stages::kHistoryIndexKey) == 2);

        // Account retrieving from Database
        account_history_data = account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false);
        REQUIRE(account_history_data.done);
        account_history_bitmap = db::bitmap::from_slice(account_history_data.value);
        REQUIRE(account_history_bitmap.cardinality() == 2);
        REQUIRE(account_history_bitmap.toString() == "{1,2}");

        // Contract retrieving from Database
        account_history_data = account_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false);
        REQUIRE(account_history_data.done);
        account_history_bitmap = db::bitmap::from_slice(account_history_data.value);
        REQUIRE(account_history_bitmap.cardinality() == 2);
        REQUIRE(account_history_bitmap.toString() == "{1,2}");

        // Storage retrieving from Database
        storage_history_data = storage_history.lower_bound(db::to_slice(composite), false);
        REQUIRE(storage_history_data.done);
        storage_history_data_view = db::from_slice(storage_history_data.key);
        REQUIRE(storage_history_data_view.starts_with(composite));
        REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) == UINT64_MAX);
        storage_history_bitmap = db::bitmap::from_slice(storage_history_data.value);
        REQUIRE(storage_history_bitmap.cardinality() == 2);
        REQUIRE(storage_history_bitmap.toString() == "{1,2}");
    }

    SECTION("Prune") {
        // Prune from second block, so we delete block 1
        // Alter node settings pruning
        db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
        db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
        beforeHistory.emplace(2);  // Will delete any history before block 2
        context.node_settings().prune_mode =
            db::parse_prune_mode("h", olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                 beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);

        REQUIRE(context.node_settings().prune_mode->history().enabled());

        stagedsync::HistoryIndex stage_history_index(&context.node_settings());
        REQUIRE(stage_history_index.forward(txn) == stagedsync::StageResult::kSuccess);
        REQUIRE(stage_history_index.prune(txn) == stagedsync::StageResult::kSuccess);
        REQUIRE(db::stages::read_stage_progress(*txn, db::stages::kHistoryIndexKey) == 3);
        REQUIRE(db::stages::read_stage_prune_progress(*txn, db::stages::kHistoryIndexKey) == 3);

        db::Cursor account_history(txn, db::table::kAccountHistory);
        db::Cursor storage_history(txn, db::table::kStorageHistory);
        REQUIRE(!account_history.empty());
        REQUIRE(!storage_history.empty());

        auto account_history_data{account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false)};
        REQUIRE(account_history_data.done);
        auto account_history_data_view{db::from_slice(account_history_data.key)};
        REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) == UINT64_MAX);
        auto account_history_bitmap{db::bitmap::from_slice(account_history_data.value)};
        REQUIRE(account_history_bitmap.cardinality() == 2);
        REQUIRE(account_history_bitmap.toString() == "{2,3}");

        auto storage_history_data{
            storage_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false)};
        REQUIRE(storage_history_data.done);
        auto storage_history_data_view{db::from_slice(storage_history_data.key)};
        REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) == UINT64_MAX);
        auto storage_history_bitmap{db::bitmap::from_slice(storage_history_data.value)};
        REQUIRE(storage_history_bitmap.cardinality() == 2);
        REQUIRE(storage_history_bitmap.toString() == "{2,3}");

        // The location is the first so it's at 0
        evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        // Composite: Address + Location
        Bytes composite(kAddressLength + kHashLength, '\0');
        std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
        std::memcpy(&composite[kAddressLength], location.bytes, kHashLength);

        // Storage retrieving from Database
        storage_history_data = storage_history.lower_bound(db::to_slice(composite), false);
        REQUIRE(storage_history_data.done);
        storage_history_data_view = db::from_slice(storage_history_data.key);
        REQUIRE(storage_history_data_view.starts_with(composite));
        REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) == UINT64_MAX);
        storage_history_bitmap = db::bitmap::from_slice(storage_history_data.value);
        REQUIRE(storage_history_bitmap.cardinality() == 2);
        REQUIRE(storage_history_bitmap.toString() == "{2,3}");
    }
}
}  // namespace silkworm
