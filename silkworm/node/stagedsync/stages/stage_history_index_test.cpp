// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/stagedsync/stages/stage_history_index.hpp>

namespace silkworm {

using namespace evmc::literals;
using namespace silkworm::db;
using namespace silkworm::datastore::kvdb;
using db::test_util::TempChainData;

stagedsync::HistoryIndex make_stage_history_index(
    stagedsync::SyncContext* sync_context,
    const TempChainData& chain_data) {
    static constexpr size_t kBatchSize = 512_Mebi;
    return stagedsync::HistoryIndex{
        sync_context,
        kBatchSize,
        datastore::etl::CollectorSettings{
            .work_path = chain_data.dir().temp().path(),
            .buffer_size = 256_Mebi},
        chain_data.prune_mode().history(),
    };
}

TEST_CASE("Stage History Index") {
    TempChainData context;
    RWTxn& txn{context.rw_txn()};
    txn.disable_commit();

    SECTION("Check bitmaps values") {
        // ---------------------------------------
        // Prepare
        // ---------------------------------------

        uint64_t block_num{1};
        auto miner{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};

        Block block{};
        block.header.number = block_num;
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

        Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};
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

        block_num = 2;
        block.header.number = block_num;
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

        block_num = 3;
        block.header.number = block_num;
        block.header.gas_used = 26'201;

        block.transactions[0].nonce = 2;
        block.transactions[0].value = 1000;

        block.transactions[0].to = contract_address;
        block.transactions[0].data = *from_hex(new_val);

        CHECK(execute_block(block, buffer, kMainnetConfig) == ValidationResult::kOk);
        buffer.write_to_db();
        stages::write_stage_progress(txn, stages::kExecutionKey, 3);

        SECTION("Forward and Unwind") {
            PooledCursor account_changes(txn, table::kAccountChangeSet);
            REQUIRE(!account_changes.empty());

            stagedsync::SyncContext sync_context{};
            stagedsync::HistoryIndex stage_history_index = make_stage_history_index(&sync_context, context);
            REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
            PooledCursor account_history(txn, table::kAccountHistory);
            PooledCursor storage_history(txn, table::kStorageHistory);
            REQUIRE(!account_history.empty());
            REQUIRE(!storage_history.empty());

            // Miner has mined 3 blocks hence is historical balance must be < current balance
            auto current_miner_account{read_account(txn, miner)};
            auto historical_miner_account{read_account(txn, miner, 2)};
            REQUIRE(current_miner_account.has_value());
            REQUIRE(historical_miner_account.has_value());
            REQUIRE(historical_miner_account->balance);
            REQUIRE(historical_miner_account->balance < current_miner_account->balance);

            auto account_history_data{account_history.lower_bound(to_slice(sender), /*throw_notfound=*/false)};
            REQUIRE(account_history_data.done);
            auto account_history_data_view{from_slice(account_history_data.key)};
            REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto account_history_bitmap{bitmap::parse(account_history_data.value)};
            REQUIRE(account_history_bitmap.cardinality() == 3);
            REQUIRE(account_history_bitmap.toString() == "{1,2,3}");

            auto storage_history_data{
                storage_history.lower_bound(to_slice(contract_address), /*throw_notfound=*/false)};
            REQUIRE(storage_history_data.done);
            auto storage_history_data_view{from_slice(storage_history_data.key)};
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto storage_history_bitmap{bitmap::parse(storage_history_data.value)};
            REQUIRE(storage_history_bitmap.cardinality() == 3);
            REQUIRE(storage_history_bitmap.toString() == "{1,2,3}");

            // The location is the first so it's at 0
            evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
            // Composite: Address + Location
            Bytes composite(kAddressLength + kHashLength, '\0');
            std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
            std::memcpy(&composite[kAddressLength], location.bytes, kHashLength);

            // Storage retrieving from Database
            storage_history_data = storage_history.lower_bound(to_slice(composite), false);
            REQUIRE(storage_history_data.done);
            storage_history_data_view = from_slice(storage_history_data.key);
            REQUIRE(storage_history_data_view.starts_with(composite));
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = bitmap::parse(storage_history_data.value);
            REQUIRE(storage_history_bitmap.cardinality() == 3);
            REQUIRE(storage_history_bitmap.toString() == "{1,2,3}");

            sync_context.unwind_point.emplace(2);
            REQUIRE(stage_history_index.unwind(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(stages::read_stage_progress(txn, stages::kHistoryIndexKey) == 2);

            // Account retrieving from Database
            account_history_data = account_history.lower_bound(to_slice(sender), /*throw_notfound=*/false);
            REQUIRE(account_history_data.done);
            account_history_bitmap = bitmap::parse(account_history_data.value);
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{1,2}");

            // Contract retrieving from Database
            account_history_data =
                account_history.lower_bound(to_slice(contract_address), /*throw_notfound=*/false);
            REQUIRE(account_history_data.done);
            account_history_bitmap = bitmap::parse(account_history_data.value);
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{1,2}");

            // Storage retrieving from Database
            storage_history_data = storage_history.lower_bound(to_slice(composite), false);
            REQUIRE(storage_history_data.done);
            storage_history_data_view = from_slice(storage_history_data.key);
            REQUIRE(storage_history_data_view.starts_with(composite));
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = bitmap::parse(storage_history_data.value);
            REQUIRE(storage_history_bitmap.cardinality() == 2);
            REQUIRE(storage_history_bitmap.toString() == "{1,2}");
        }

        SECTION("Prune") {
            // Prune from second block, so we delete block 1
            // Alter node settings pruning
            PruneDistance older_history, older_receipts, older_senders, older_tx_index, older_call_traces;
            PruneThreshold before_history, before_receipts, before_senders, before_tx_index, before_call_traces;
            before_history.emplace(2);  // Will delete any history before block 2
            context.set_prune_mode(
                parse_prune_mode("h", older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                                 before_history, before_receipts, before_senders, before_tx_index, before_call_traces));

            REQUIRE(context.prune_mode().history().enabled());

            stagedsync::SyncContext sync_context{};
            stagedsync::HistoryIndex stage_history_index = make_stage_history_index(&sync_context, context);
            REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(stage_history_index.prune(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(stages::read_stage_progress(txn, stages::kHistoryIndexKey) == 3);
            REQUIRE(stages::read_stage_prune_progress(txn, stages::kHistoryIndexKey) == 3);

            PooledCursor account_history(txn, table::kAccountHistory);
            PooledCursor storage_history(txn, table::kStorageHistory);
            REQUIRE(!account_history.empty());
            REQUIRE(!storage_history.empty());

            auto account_history_data{account_history.lower_bound(to_slice(sender), /*throw_notfound=*/false)};
            REQUIRE(account_history_data.done);
            auto account_history_data_view{from_slice(account_history_data.key)};
            REQUIRE(endian::load_big_u64(&account_history_data_view[account_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto account_history_bitmap{bitmap::parse(account_history_data.value)};
            REQUIRE(account_history_bitmap.cardinality() == 2);
            REQUIRE(account_history_bitmap.toString() == "{2,3}");

            auto storage_history_data{
                storage_history.lower_bound(to_slice(contract_address), /*throw_notfound=*/false)};
            REQUIRE(storage_history_data.done);
            auto storage_history_data_view{from_slice(storage_history_data.key)};
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            auto storage_history_bitmap{bitmap::parse(storage_history_data.value)};
            REQUIRE(storage_history_bitmap.cardinality() == 2);
            REQUIRE(storage_history_bitmap.toString() == "{2,3}");

            // The location is the first so it's at 0
            evmc::bytes32 location{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
            // Composite: Address + Location
            Bytes composite(kAddressLength + kHashLength, '\0');
            std::memcpy(&composite[0], contract_address.bytes, kAddressLength);
            std::memcpy(&composite[kAddressLength], location.bytes, kHashLength);

            // Storage retrieving from Database
            storage_history_data = storage_history.lower_bound(to_slice(composite), false);
            REQUIRE(storage_history_data.done);
            storage_history_data_view = from_slice(storage_history_data.key);
            REQUIRE(storage_history_data_view.starts_with(composite));
            REQUIRE(endian::load_big_u64(&storage_history_data_view[storage_history_data_view.size() - 8]) ==
                    UINT64_MAX);
            storage_history_bitmap = bitmap::parse(storage_history_data.value);
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
        PooledCursor account_changeset(txn, table::kAccountChangeSet);
        BlockNum block_num = 1;

        for (; block_num <= 50000; ++block_num) {
            const auto block_key{db::block_key(block_num)};
            for (const auto& address : addresses) {
                Bytes value(kAddressLength, '\0');
                std::memcpy(&value[0], address.bytes, kAddressLength);
                value.append(non_empty);
                auto value_slice{to_slice(value)};
                mdbx::error::success_or_throw(
                    account_changeset.put(to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
            }
        }

        // Fake generation of changesets
        stages::write_stage_progress(txn, stages::kExecutionKey, block_num - 1);

        // Forward history
        stagedsync::SyncContext sync_context{};
        stagedsync::HistoryIndex stage_history_index = make_stage_history_index(&sync_context, context);
        REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);
        PooledCursor account_history(txn, table::kAccountHistory);
        auto batch_1{account_history.size()};
        REQUIRE(batch_1 != 0);

        auto check_addresses{[&account_history, &block_num](const std::vector<evmc::address>& addrs) {
            for (const auto& address : addrs) {
                Bytes key(kAddressLength, '\0');
                std::memcpy(&key[0], address.bytes, kAddressLength);
                key.append(block_key(UINT64_MAX));

                bool has_thrown{false};
                try {
                    auto data = account_history.find(to_slice(key), /*throw_notfound=*/true);
                    auto bitmap{bitmap::parse(data.value)};
                    REQUIRE(bitmap.maximum() == block_num - 1);
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
                cursor_for_prefix(account_history, prefix,
                                  [](ByteView, ByteView) {})};
            REQUIRE(count == 2);
        }

        // Add one address and store changes from current block_num onwards
        {
            addresses.push_back(0x0000000000000000000000000000000000000004_address);
            const auto block_key{db::block_key(block_num++)};
            Bytes value(kAddressLength, '\0');
            std::memcpy(&value[0], addresses.back().bytes, kAddressLength);
            auto value_slice{to_slice(value)};
            mdbx::error::success_or_throw(
                account_changeset.put(to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
        }

        for (; block_num <= 100000; ++block_num) {
            const auto block_key{db::block_key(block_num)};
            for (const auto& address : addresses) {
                Bytes value(kAddressLength, '\0');
                std::memcpy(&value[0], address.bytes, kAddressLength);
                value.append(non_empty);
                auto value_slice{to_slice(value)};
                mdbx::error::success_or_throw(
                    account_changeset.put(to_slice(block_key), &value_slice, MDBX_put_flags_t::MDBX_APPENDDUP));
            }
        }
        stages::write_stage_progress(txn, stages::kExecutionKey, block_num - 1);
        txn.commit_and_renew();

        REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);

        account_history.bind(txn, table::kAccountHistory);
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
                cursor_for_prefix(account_history, prefix,
                                  [](ByteView, ByteView) {})};
            REQUIRE(count == 0);
            addresses.pop_back();  // Remove unused address for next tests
        }

        // Each key must have only 1 record now which has UINT64_MAX suffix
        for (const auto& address : addresses) {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], address.bytes, kAddressLength);
            auto count{cursor_for_prefix(
                account_history, prefix, [](ByteView key, ByteView value) {
                    CHECK(endian::load_big_u64(&key[key.size() - sizeof(BlockNum)]) == UINT64_MAX);
                    const auto bitmap{bitmap::parse(value)};
                    CHECK(bitmap.maximum() == 4000);
                })};
            REQUIRE(count == 1);
        }

        // Prune from block 3590
        // Alter node settings pruning
        PruneDistance older_history, older_receipts, older_senders, older_tx_index, older_call_traces;
        PruneThreshold before_history, before_receipts, before_senders, before_tx_index, before_call_traces;
        before_history.emplace(3590);  // Will delete any history before block 2
        context.set_prune_mode(
            parse_prune_mode("h", older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                             before_history, before_receipts, before_senders, before_tx_index, before_call_traces));
        REQUIRE(context.prune_mode().history().enabled());

        // Recreate the stage with enabled pruning
        stagedsync::HistoryIndex stage_history_index2 = make_stage_history_index(&sync_context, context);

        REQUIRE(stage_history_index2.prune(txn) == stagedsync::Stage::Result::kSuccess);

        // Each key must have only 1 record now which has UINT64_MAX suffix AND bitmap max value must be 3590
        for (const auto& address : addresses) {
            Bytes prefix(kAddressLength, '\0');
            std::memcpy(&prefix[0], address.bytes, kAddressLength);
            auto count{cursor_for_prefix(
                account_history, prefix, [](ByteView key, ByteView value) {
                    CHECK(endian::load_big_u64(&key[key.size() - sizeof(BlockNum)]) == UINT64_MAX);
                    const auto bitmap{bitmap::parse(value)};
                    CHECK(bitmap.minimum() == 3590);
                })};
            REQUIRE(count == 1);
        }
    }
}

TEST_CASE("HistoryIndex + Account access_layer") {
    TempChainData context;
    RWTxn& txn{context.rw_txn()};

    Buffer buffer{txn, std::make_unique<BufferROTxDataModel>(txn)};

    const evmc::address miner_a{0x00000000000000000000000000000000000000aa_address};
    const evmc::address miner_b{0x00000000000000000000000000000000000000bb_address};

    Block block1;
    block1.header.number = 1;
    block1.header.beneficiary = miner_a;
    // miner_a gets one block reward
    REQUIRE(execute_block(block1, buffer, test::kFrontierConfig) == ValidationResult::kOk);

    Block block2;
    block2.header.number = 2;
    block2.header.beneficiary = miner_b;
    // miner_a gets nothing
    REQUIRE(execute_block(block2, buffer, test::kFrontierConfig) == ValidationResult::kOk);

    Block block3;
    block3.header.number = 3;
    block3.header.beneficiary = miner_a;
    // miner_a gets another block reward
    REQUIRE(execute_block(block3, buffer, test::kFrontierConfig) == ValidationResult::kOk);

    buffer.write_to_db();
    stages::write_stage_progress(txn, stages::kExecutionKey, 3);

    stagedsync::SyncContext sync_context{};
    stagedsync::HistoryIndex stage_history_index = make_stage_history_index(&sync_context, context);
    REQUIRE(stage_history_index.forward(txn) == stagedsync::Stage::Result::kSuccess);

    std::optional<Account> current_account{read_account(txn, miner_a)};
    REQUIRE(current_account.has_value());
    CHECK(current_account->balance == 2 * protocol::kBlockRewardFrontier);

    std::optional<Account> historical_account{read_account(txn, miner_a, /*block_num=*/2)};
    REQUIRE(historical_account.has_value());
    CHECK(intx::to_string(historical_account->balance) == std::to_string(protocol::kBlockRewardFrontier));

    std::optional<uint64_t> previous_incarnation{read_previous_incarnation(txn, miner_a, /*block_num=*/2)};
    REQUIRE(previous_incarnation.has_value());
    CHECK(previous_incarnation == 0);
}

}  // namespace silkworm
