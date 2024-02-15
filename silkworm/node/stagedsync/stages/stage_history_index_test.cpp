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

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/bitmap.hpp>
#include <silkworm/node/db/buffer.hpp>
#include <silkworm/node/db/stages.hpp>
#include <silkworm/node/db/test_util/temp_chain_data.hpp>
#include <silkworm/node/stagedsync/stages/stage_history_index.hpp>
#include <silkworm/node/test_util/temp_chain_data_node_settings.hpp>

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Stage History Index") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    db::test_util::TempChainData context;
    db::RWTxn& txn{context.rw_txn()};
    txn.disable_commit();

    SECTION("Check bitmaps values") {
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
        block.transactions[0].set_sender(sender);

        db::Buffer buffer{txn, 0};
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
        buffer.write_to_db(txn);
        db::stages::write_stage_progress(txn, db::stages::kExecutionKey, 3);

        SECTION("Forward and Unwind") {
            db::PooledCursor account_changes(txn, db::table::kAccountChangeSet);
            REQUIRE(!account_changes.empty());

            NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
            stagedsync::SyncContext sync_context{};
            stagedsync::HistoryIndex stage_history_index(&node_settings, &sync_context);
            REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
            db::PooledCursor account_history(txn, db::table::kAccountHistory);
            db::PooledCursor storage_history(txn, db::table::kStorageHistory);
            REQUIRE(!account_history.empty());
            REQUIRE(!storage_history.empty());

            // Miner has mined 3 blocks hence is historical balance must be < current balance
            auto current_miner_account{db::read_account(txn, miner)};
            auto historical_miner_account{db::read_account(txn, miner, 2)};
            REQUIRE(current_miner_account.has_value());
            REQUIRE(historical_miner_account.has_value());
            REQUIRE(historical_miner_account->balance);
            REQUIRE(historical_miner_account->balance < current_miner_account->balance);

            auto account_history_data{account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false)};
            REQUIRE(account_history_data.done);
            auto account_history_data_view{db::from_slice(account_history_data.key)};
            REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto account_history_bitmap{db::bitmap::parse(account_history_data.value)};
            REQUIRE(account_history_bitmap.cardinality() == 3);
            REQUIRE(account_history_bitmap.toString() == "{1,2,3}");

            auto storage_history_data{
                storage_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false)};
            REQUIRE(storage_history_data.done);
            auto storage_history_data_view{db::from_slice(storage_history_data.key)};
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto storage_history_bitmap{db::bitmap::parse(storage_history_data.value)};
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
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = db::bitmap::parse(storage_history_data.value);
            REQUIRE(storage_history_bitmap.cardinality() == 3);
            REQUIRE(storage_history_bitmap.toString() == "{1,2,3}");

            sync_context.unwind_point.emplace(2);
            REQUIRE(stage_history_index.unwind(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(db::stages::read_stage_progress(txn, db::stages::kHistoryIndexKey) == 2);

            // Account retrieving from Database
            account_history_data = account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false);
            REQUIRE(account_history_data.done);
            account_history_bitmap = db::bitmap::parse(account_history_data.value);
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{1,2}");

            // Contract retrieving from Database
            account_history_data =
                account_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false);
            REQUIRE(account_history_data.done);
            account_history_bitmap = db::bitmap::parse(account_history_data.value);
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{1,2}");

            // Storage retrieving from Database
            storage_history_data = storage_history.lower_bound(db::to_slice(composite), false);
            REQUIRE(storage_history_data.done);
            storage_history_data_view = db::from_slice(storage_history_data.key);
            REQUIRE(storage_history_data_view.starts_with(composite));
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = db::bitmap::parse(storage_history_data.value);
            REQUIRE(storage_history_bitmap.cardinality() == 2);
            REQUIRE(storage_history_bitmap.toString() == "{1,2}");
        }

        SECTION("Prune") {
            // Prune from second block, so we delete block 1
            // Alter node settings pruning
            db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
            db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
            beforeHistory.emplace(2);  // Will delete any history before block 2
            context.set_prune_mode(
                db::parse_prune_mode("h", olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                     beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces));

            REQUIRE(context.prune_mode().history().enabled());

            NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
            stagedsync::SyncContext sync_context{};
            stagedsync::HistoryIndex stage_history_index(&node_settings, &sync_context);
            REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(stage_history_index.prune(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(db::stages::read_stage_progress(txn, db::stages::kHistoryIndexKey) == 3);
            REQUIRE(db::stages::read_stage_prune_progress(txn, db::stages::kHistoryIndexKey) == 3);

            db::PooledCursor account_history(txn, db::table::kAccountHistory);
            db::PooledCursor storage_history(txn, db::table::kStorageHistory);
            REQUIRE(!account_history.empty());
            REQUIRE(!storage_history.empty());

            auto account_history_data{account_history.lower_bound(db::to_slice(sender), /*throw_notfound=*/false)};
            REQUIRE(account_history_data.done);
            auto account_history_data_view{db::from_slice(account_history_data.key)};
            REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto account_history_bitmap{db::bitmap::parse(account_history_data.value)};
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{2,3}");

            auto storage_history_data{
                storage_history.lower_bound(db::to_slice(contract_address), /*throw_notfound=*/false)};
            REQUIRE(storage_history_data.done);
            auto storage_history_data_view{db::from_slice(storage_history_data.key)};
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto storage_history_bitmap{db::bitmap::parse(storage_history_data.value)};
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
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = db::bitmap::parse(storage_history_data.value);
            REQUIRE(storage_history_bitmap.cardinality() == 2);
            REQUIRE(storage_history_bitmap.toString() == "{2,3}");
        }
    }

    SECTION("Large dataset") {
        const Bytes non_empty(1, '\1');
        std::vector<evmc::address> addresses{{0x0000000000000000000000000000000000000001_address},
                                             {0x0000000000000000000000000000000000000002_address},
                                             {0x0000000000000000000000000000000000000003_address}};

        // Use a large dataset in change sets (actual values do not matter)
        db::PooledCursor account_changeset(txn, db::table::kAccountChangeSet);
        BlockNum block{1};

        for (; block <= 50000; ++block) {
            const auto block_key{db::block_key(block)};
            for (const auto& address : addresses) {
                Bytes value(kAddressLength, '\0');
                std::memcpy(&value[0], address.bytes, kAddressLength);
                value.append(non_empty);
                auto value_slice{db::to_slice(value)};
                mdbx::error::success_or_throw(
                    account_changeset.put(db::to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
            }
        }

        // Fake generation of changesets
        db::stages::write_stage_progress(txn, db::stages::kExecutionKey, block - 1);

        // Forward history
        NodeSettings node_settings = node::test_util::make_node_settings_from_temp_chain_data(context);
        stagedsync::SyncContext sync_context{};
        stagedsync::HistoryIndex stage_history_index(&node_settings, &sync_context);
        REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
        db::PooledCursor account_history(txn, db::table::kAccountHistory);
        auto batch_1{account_history.size()};
        REQUIRE(batch_1 != 0);

        auto check_addresses{[&account_history, &block](const std::vector<evmc::address>& addrs) {
            for (const auto& address : addrs) {
                Bytes key(kAddressLength, '\0');
                std::memcpy(&key[0], address.bytes, kAddressLength);
                key.append(db::block_key(UINT64_MAX));

                bool has_thrown{false};
                try {
                    auto data = account_history.find(db::to_slice(key), /*throw_notfound=*/true);
                    auto bitmap{db::bitmap::parse(data.value)};
                    REQUIRE(bitmap.maximum() == block - 1);
                } catch (...) {
                    has_thrown = true;
                }
                REQUIRE_FALSE(has_thrown);
            }
        }};

        // Ensure each of the accounts has a record in history with key address + UINT64_MAX(BE)
        // and it's stored bitmap as a maximum value of 5000
        check_addresses(addresses);

        // Given the amount of blocks each address should hold 2 shards
        for (const auto& address : addresses) {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], address.bytes, kAddressLength);
            auto count{
                db::cursor_for_prefix(account_history, prefix,
                                      [](ByteView, ByteView) {})};
            REQUIRE(count == 2);
        }

        // Add one address and store changes from current height onwards
        {
            addresses.push_back(0x0000000000000000000000000000000000000004_address);
            const auto block_key{db::block_key(block++)};
            Bytes value(kAddressLength, '\0');
            std::memcpy(&value[0], addresses.back().bytes, kAddressLength);
            auto value_slice{db::to_slice(value)};
            mdbx::error::success_or_throw(
                account_changeset.put(db::to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
        }

        for (; block <= 100000; ++block) {
            const auto block_key{db::block_key(block)};
            for (const auto& address : addresses) {
                Bytes value(kAddressLength, '\0');
                std::memcpy(&value[0], address.bytes, kAddressLength);
                value.append(non_empty);
                auto value_slice{db::to_slice(value)};
                mdbx::error::success_or_throw(
                    account_changeset.put(db::to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
            }
        }
        db::stages::write_stage_progress(txn, db::stages::kExecutionKey, block - 1);
        txn.commit_and_renew();

        REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);

        account_history.bind(txn, db::table::kAccountHistory);
        REQUIRE(batch_1 < account_history.size());
        check_addresses(addresses);
        txn.commit_and_renew();

        // Unwind to 4000 and ensure account 4 has been removed from history
        sync_context.unwind_point.emplace(4'000);
        REQUIRE(stage_history_index.unwind(txn) == stagedsync::Stage::Result::kSuccess);
        {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], addresses.back().bytes, kAddressLength);
            auto count{
                db::cursor_for_prefix(account_history, prefix,
                                      [](ByteView, ByteView) {})};
            REQUIRE(count == 0);
            addresses.pop_back();  // Remove unused address for next tests
        }

        // Each key must have only 1 record now which has UINT64_MAX suffix
        for (const auto& address : addresses) {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], address.bytes, kAddressLength);
            auto count{db::cursor_for_prefix(
                account_history, prefix, [](ByteView key, ByteView value) {
                    CHECK(endian::load_big_u64(&key[key.size() - sizeof(BlockNum)]) == UINT64_MAX);
                    const auto bitmap{db::bitmap::parse(value)};
                    CHECK(bitmap.maximum() == 4000);
                })};
            REQUIRE(count == 1);
        }

        // Prune from block 3590
        // Alter node settings pruning
        db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
        db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;
        beforeHistory.emplace(3590);  // Will delete any history before block 2
        context.set_prune_mode(
            db::parse_prune_mode("h", olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                 beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces));
        REQUIRE(context.prune_mode().history().enabled());

        // Recreate the stage with enabled pruning
        NodeSettings node_settings2 = node::test_util::make_node_settings_from_temp_chain_data(context);
        stagedsync::HistoryIndex stage_history_index2(&node_settings2, &sync_context);

        REQUIRE(stage_history_index2.prune(txn) == stagedsync::Stage::Result::kSuccess);

        // Each key must have only 1 record now which has UINT64_MAX suffix AND bitmap max value must be 3590
        for (const auto& address : addresses) {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], address.bytes, kAddressLength);
            auto count{db::cursor_for_prefix(
                account_history, prefix, [](ByteView key, ByteView value) {
                    CHECK(endian::load_big_u64(&key[key.size() - sizeof(BlockNum)]) == UINT64_MAX);
                    const auto bitmap{db::bitmap::parse(value)};
                    CHECK(bitmap.minimum() == 3590);
                })};
            REQUIRE(count == 1);
        }
    }

    log::set_verbosity(log::Level::kInfo);
}

}  // namespace silkworm
