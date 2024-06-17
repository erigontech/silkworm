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

#include <catch2/catch_test_macros.hpp>
#include <magic_enum.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/common/node_settings.hpp>
#include <silkworm/node/stagedsync/stages/stage_blockhashes.hpp>
#include <silkworm/node/stagedsync/stages/stage_call_trace_index.hpp>
#include <silkworm/node/stagedsync/stages/stage_execution.hpp>
#include <silkworm/node/stagedsync/stages/stage_hashstate.hpp>
#include <silkworm/node/stagedsync/stages/stage_senders.hpp>

using namespace silkworm;
using namespace evmc::literals;

static ethash::hash256 keccak256(const evmc::address& address) {
    return silkworm::keccak256(address.bytes);
}

static stagedsync::Execution make_execution_stage(
    stagedsync::SyncContext* sync_context,
    const NodeSettings& node_settings) {
    return stagedsync::Execution{
        sync_context,
        *node_settings.chain_config,
        node_settings.batch_size,
        node_settings.prune_mode,
    };
}

static stagedsync::CallTraceIndex make_call_traces_stage(
    stagedsync::SyncContext* sync_context,
    const NodeSettings& node_settings) {
    return stagedsync::CallTraceIndex{
        sync_context,
        node_settings.batch_size,
        node_settings.etl(),
        node_settings.prune_mode.call_traces(),
    };
}

TEST_CASE("Sync Stages") {
    TemporaryDirectory temp_dir{};
    NodeSettings node_settings{};
    node_settings.data_directory = std::make_unique<DataDirectory>(temp_dir.path());
    node_settings.data_directory->deploy();
    node_settings.chaindata_env_config.path = node_settings.data_directory->chaindata().path().string();
    node_settings.chaindata_env_config.max_size = 1_Gibi;      // Small enough to fit in memory
    node_settings.chaindata_env_config.growth_size = 10_Mebi;  // Small increases
    node_settings.chaindata_env_config.in_memory = true;
    node_settings.chaindata_env_config.create = true;
    node_settings.chaindata_env_config.exclusive = true;
    node_settings.prune_mode =
        db::parse_prune_mode("",
                             std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                             std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);

    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};

    auto chaindata_env{db::open_env(node_settings.chaindata_env_config)};
    db::RWTxnManaged txn(chaindata_env);
    db::table::check_or_create_chaindata_tables(txn);
    txn.commit_and_renew();
    const auto initial_tx_sequence{db::read_map_sequence(txn, db::table::kBlockTransactions.name)};
    REQUIRE(initial_tx_sequence == 0);  // no txs at start

    auto source_data{read_genesis_data(node_settings.network_id)};
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
    db::initialize_genesis(txn, genesis_json, /*allow_exceptions=*/true);
    txn.commit_and_renew();
    node_settings.chain_config = db::read_chain_config(txn);
    const auto tx_sequence_after_genesis{db::read_map_sequence(txn, db::table::kBlockTransactions.name)};
    REQUIRE(tx_sequence_after_genesis == 2);  // 2 system txs for genesis

    SECTION("BlockHashes") {
        SECTION("Forward/Unwind/Prune args validation") {
            stagedsync::SyncContext sync_context{};
            stagedsync::BlockHashes stage(&sync_context, node_settings.etl());

            // (previous_progress == headers_progress == 0)
            REQUIRE(stage.forward(txn) == stagedsync::Stage::Result::kSuccess);
            REQUIRE(stage.unwind(txn) == stagedsync::Stage::Result::kSuccess);

            // (previous_progress > headers_progress)
            stage.update_progress(txn, 10);
            REQUIRE(stage.forward(txn) == stagedsync::Stage::Result::kInvalidProgress);
        }

        SECTION("Forward and Unwind") {
            std::vector<evmc::bytes32> block_hashes = {
                0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32,
                0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32,
                0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

            db::PooledCursor canonical_table(txn, db::table::kCanonicalHashes);
            BlockNum block_num{1};
            for (const auto& hash : block_hashes) {
                Bytes block_key{db::block_key(block_num++)};
                canonical_table.insert(db::to_slice(block_key), db::to_slice(hash));
            }
            db::stages::write_stage_progress(txn, db::stages::kHeadersKey, 3);
            REQUIRE_NOTHROW(txn.commit_and_renew());

            stagedsync::SyncContext sync_context{};
            stagedsync::BlockHashes stage(&sync_context, node_settings.etl());

            // Forward
            auto stage_result{stage.forward(txn)};
            REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);
            txn.commit_and_renew();

            {
                // Verify written data is consistent
                db::PooledCursor target_table{txn, db::table::kHeaderNumbers};

                REQUIRE(txn->get_map_stat(target_table.map()).ms_entries ==
                        block_hashes.size() + 1);  // +1 cause block 0 is genesis

                std::vector<std::pair<evmc::bytes32, BlockNum>> written_data{};
                auto walk_func = [&written_data](ByteView key, ByteView value) {
                    auto written_block_num{endian::load_big_u64(value.data())};
                    auto written_hash{to_bytes32(key)};
                    written_data.emplace_back(written_hash, written_block_num);
                };
                db::cursor_for_each(target_table, walk_func);

                REQUIRE(written_data.size() == block_hashes.size() + 1);
                for (const auto& [written_hash, written_block_num] : written_data) {
                    REQUIRE(written_block_num < block_hashes.size() + 1);
                    if (written_block_num) {
                        REQUIRE(written_hash == block_hashes.at(written_block_num - 1));
                    }
                }
            }

            // Unwind
            sync_context.unwind_point.emplace(1);
            stage_result = stage.unwind(txn);
            REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);
            {
                // Verify written data is consistent
                db::PooledCursor target_table(txn, db::table::kHeaderNumbers);
                REQUIRE(txn->get_map_stat(target_table.map()).ms_entries == 4);
                REQUIRE(target_table.seek(db::to_slice(block_hashes.back())));
            }
        }
    }

    SECTION("Senders") {
        std::vector<evmc::bytes32> block_hashes{
            0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32,
            0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32,
            0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

        auto sample_transactions{test::sample_transactions()};

        BlockBody block_body;

        // First block - 1 transaction
        block_body.transactions.push_back(sample_transactions[0]);
        REQUIRE_NOTHROW(db::write_body(txn, block_body, block_hashes[0].bytes, 1));
        const auto tx_sequence_after_block1{db::read_map_sequence(txn, db::table::kBlockTransactions.name)};
        REQUIRE(tx_sequence_after_block1 == 5);  // 1 tx + 2 system txs for block 1

        // Second block - 1 transactions
        REQUIRE_NOTHROW(db::write_body(txn, block_body, block_hashes[1].bytes, 2));
        const auto tx_sequence_after_block2{db::read_map_sequence(txn, db::table::kBlockTransactions.name)};
        REQUIRE(tx_sequence_after_block2 == 8);  // 1 tx + 2 system txs for block 2

        // Third block - 0 transactions
        block_body.transactions.clear();
        REQUIRE_NOTHROW(db::write_body(txn, block_body, block_hashes[2].bytes, 3));

        // Write canonical hashes
        REQUIRE_NOTHROW(db::write_canonical_header_hash(txn, block_hashes[0].bytes, 1));
        REQUIRE_NOTHROW(db::write_canonical_header_hash(txn, block_hashes[1].bytes, 2));
        REQUIRE_NOTHROW(db::write_canonical_header_hash(txn, block_hashes[2].bytes, 3));

        // Update progresses
        REQUIRE_NOTHROW(db::stages::write_stage_progress(txn, db::stages::kBlockBodiesKey, 3));
        REQUIRE_NOTHROW(db::stages::write_stage_progress(txn, db::stages::kBlockHashesKey, 3));

        // Commit
        REQUIRE_NOTHROW(txn.commit_and_renew());

        // Verify sequence for transactions has been incremented properly
        const auto last_tx_sequence{db::read_map_sequence(txn, db::table::kBlockTransactions.name)};
        REQUIRE(last_tx_sequence == 10);  // 2 system txs for block 3

        // Prepare stage
        stagedsync::SyncContext sync_context{};
        stagedsync::Senders stage{
            &sync_context,
            *node_settings.chain_config,
            node_settings.batch_size,
            node_settings.etl(),
            node_settings.prune_mode.senders(),
        };

        // Insert a martian stage progress
        stage.update_progress(txn, 5);
        auto stage_result = stage.forward(txn);
        REQUIRE(stage_result != stagedsync::Stage::Result::kSuccess);

        // Check forward works
        stage.update_progress(txn, 0);
        stage_result = stage.forward(txn);
        REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);
        REQUIRE(stage.get_progress(txn) == 3);

        // Executing once again with no changes should do nothing
        stage_result = stage.forward(txn);
        REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);
        REQUIRE(stage.get_progress(txn) == 3);

        REQUIRE_NOTHROW(txn.commit_and_renew());

        {
            auto senders_map{txn->open_map(db::table::kSenders.name)};
            REQUIRE(txn->get_map_stat(senders_map).ms_entries == 2);

            auto expected_sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};
            auto written_senders{db::read_senders(txn, 1, block_hashes[0].bytes)};
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(txn, 2, block_hashes[1].bytes);
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(txn, 3, block_hashes[2].bytes);
            REQUIRE(written_senders.empty());
        }

        // Check unwind works
        sync_context.unwind_point.emplace(1);
        stage_result = stage.unwind(txn);
        REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);

        {
            auto senders_map{txn->open_map(db::table::kSenders.name)};
            REQUIRE(txn->get_map_stat(senders_map).ms_entries == 1);

            auto expected_sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};
            auto written_senders{db::read_senders(txn, 1, block_hashes[0].bytes)};
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(txn, 2, block_hashes[1].bytes);
            REQUIRE(written_senders.empty());

            written_senders = db::read_senders(txn, 3, block_hashes[2].bytes);
            REQUIRE(written_senders.empty());
        }

        // Check prune works
        // Override prune mode and issue pruning
        stage.set_prune_mode_senders(db::BlockAmount(db::BlockAmount::Type::kBefore, 2));
        stage_result = stage.prune(txn);
        REQUIRE(stage_result == stagedsync::Stage::Result::kSuccess);
        auto written_senders{db::read_senders(txn, 1, block_hashes[0].bytes)};
        REQUIRE(written_senders.empty());
    }

    SECTION("Execution and HashState") {
        using namespace magic_enum;
        using StageResult = stagedsync::Stage::Result;

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

        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        std::vector<Receipt> receipts{
            {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
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
        block.transactions[0].type = TransactionType::kLegacy;

        auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
        block.transactions[0].r = 1;  // dummy
        block.transactions[0].s = 1;  // dummy
        block.transactions[0].set_sender(sender);

        db::Buffer buffer{txn};
        Account sender_account{};
        sender_account.balance = kEther;
        buffer.update_account(sender, std::nullopt, sender_account);

        // ---------------------------------------
        // Execute first block
        // ---------------------------------------
        auto actual_validation_result = execute_block(block, buffer, node_settings.chain_config.value());
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        REQUIRE((enum_name(actual_validation_result) == enum_name(ValidationResult::kOk)));
        auto contract_address{create_address(sender, /*nonce=*/0)};

        // ---------------------------------------
        // Execute second block
        // ---------------------------------------
        auto new_val{0x000000000000000000000000000000000000000000000000000000000000003e_bytes32};

        block_number = 2;
        block.header.number = block_number;
        block.header.gas_used = 26'201;
        receipts[0].cumulative_gas_used = block.header.gas_used;
        block.header.receipts_root = trie::root_hash(receipts, kEncoder);

        block.transactions[0].nonce = 1;
        block.transactions[0].value = 1000;
        block.transactions[0].to = contract_address;
        block.transactions[0].data = ByteView(new_val);

        actual_validation_result = execute_block(block, buffer, node_settings.chain_config.value());
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        REQUIRE((enum_name(actual_validation_result) == enum_name(ValidationResult::kOk)));

        // ---------------------------------------
        // Execute third block
        // ---------------------------------------

        new_val = 0x000000000000000000000000000000000000000000000000000000000000003b_bytes32;

        block_number = 3;
        block.header.number = block_number;
        block.transactions[0].nonce = 2;
        block.transactions[0].value = 1000;
        block.transactions[0].to = contract_address;
        block.transactions[0].data = ByteView{new_val};

        actual_validation_result = execute_block(block, buffer, node_settings.chain_config.value());
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        REQUIRE((enum_name(actual_validation_result) == enum_name(ValidationResult::kOk)));
        REQUIRE_NOTHROW(buffer.write_to_db());
        REQUIRE_NOTHROW(db::stages::write_stage_progress(txn, db::stages::kExecutionKey, 3));
        REQUIRE_NOTHROW(txn.commit_and_renew());

        SECTION("Execution Unwind") {
            // ---------------------------------------
            // Unwind 3rd block and checks if state is second block
            // ---------------------------------------
            stagedsync::SyncContext sync_context{};
            sync_context.unwind_point.emplace(2);
            stagedsync::Execution stage = make_execution_stage(&sync_context, node_settings);
            REQUIRE(stage.unwind(txn) == stagedsync::Stage::Result::kSuccess);

            db::Buffer buffer2{txn};

            std::optional<Account> contract_account{buffer2.read_account(contract_address)};
            REQUIRE(contract_account.has_value());
            CHECK(contract_account.value().balance == intx::uint256{1000});  // 2000 - 1000

            std::optional<Account> current_sender{buffer2.read_account(sender)};
            REQUIRE(current_sender.has_value());
            CHECK(intx::to_string(current_sender.value().balance) == std::to_string(kEther - 1000));
            CHECK(current_sender.value().nonce == 2);  // Nonce at 2nd block

            ethash::hash256 code_hash{keccak256(contract_code)};
            CHECK(to_hex(contract_account->code_hash) == to_hex(code_hash.bytes));

            evmc::bytes32 storage_key0{};
            evmc::bytes32 storage0{buffer2.read_storage(contract_address, kDefaultIncarnation, storage_key0)};
            CHECK(storage0 == 0x000000000000000000000000000000000000000000000000000000000000003e_bytes32);
        }

        SECTION("Execution Prune Default") {
            log::Info() << "Pruning with " << node_settings.prune_mode.to_string();
            stagedsync::SyncContext sync_context{};
            stagedsync::Execution stage = make_execution_stage(&sync_context, node_settings);
            REQUIRE(stage.prune(txn) == stagedsync::Stage::Result::kSuccess);

            // With default settings nothing should be pruned
            db::PooledCursor account_changeset_table(txn, db::table::kAccountChangeSet);
            auto data{account_changeset_table.to_first(false)};
            REQUIRE(data.done);
            BlockNum expected_block_num{0};  // We have account changes from genesis
            auto actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);

            db::PooledCursor storage_changeset_table(txn, db::table::kStorageChangeSet);
            data = storage_changeset_table.to_first(false);
            REQUIRE(data.done);
            expected_block_num = 1;  // First storage change is at block 1
            actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);

            // There is no pruning setting enabled hence no pruning occurred
            REQUIRE(db::stages::read_stage_prune_progress(txn, db::stages::kExecutionKey) == 0);
        }

        SECTION("Execution Prune History") {
            // Override prune mode and issue pruning
            node_settings.prune_mode =
                db::parse_prune_mode("", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 2,
                                     std::nullopt, std::nullopt, std::nullopt, std::nullopt);

            log::Info() << "Pruning with " << node_settings.prune_mode.to_string();
            REQUIRE(node_settings.prune_mode.history().enabled());
            stagedsync::SyncContext sync_context{};
            stagedsync::Execution stage = make_execution_stage(&sync_context, node_settings);
            REQUIRE(stage.prune(txn) == stagedsync::Stage::Result::kSuccess);

            db::PooledCursor account_changeset_table(txn, db::table::kAccountChangeSet);
            auto data{account_changeset_table.to_first(false)};
            REQUIRE(data.done);
            BlockNum expected_block_num = 2;  // We've pruned history *before* 2 so the last is 2
            BlockNum actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);
            REQUIRE(db::stages::read_stage_prune_progress(txn, db::stages::kExecutionKey) == 3);
        }

        SECTION("HashState") {
            stagedsync::SyncContext sync_context{};
            stagedsync::HashState stage{&sync_context, node_settings.etl()};
            auto actual_stage_result = stage.forward(txn);
            // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
            REQUIRE((enum_name(actual_stage_result) == enum_name(StageResult::kSuccess)));
            REQUIRE(db::stages::read_stage_progress(txn, db::stages::kHashStateKey) == 3);

            // ---------------------------------------
            // Check hashed account
            // ---------------------------------------
            db::PooledCursor hashed_accounts_table(txn, db::table::kHashedAccounts);
            auto hashed_sender{keccak256(sender)};
            REQUIRE(hashed_accounts_table.seek(db::to_slice(hashed_sender.bytes)));
            {
                auto account_encoded{db::from_slice(hashed_accounts_table.current().value)};
                auto account{Account::from_encoded_storage(account_encoded)};
                CHECK(account->nonce == 3);
                CHECK(account->balance < kEther);
            }

            // ---------------------------------------
            // Check hashed storage
            // ---------------------------------------
            db::PooledCursor hashed_storage_table(txn, db::table::kHashedStorage);
            auto hashed_contract{keccak256(contract_address)};
            Bytes storage_key{db::storage_prefix(hashed_contract.bytes, kDefaultIncarnation)};
            REQUIRE(hashed_storage_table.find(db::to_slice(storage_key)));
            REQUIRE(hashed_storage_table.count_multivalue() == 2);

            // location 0
            auto hashed_loc0{keccak256((0x0000000000000000000000000000000000000000000000000000000000000000_bytes32).bytes)};
            hashed_storage_table.to_current_first_multi();
            mdbx::slice db_val{hashed_storage_table.current().value};
            REQUIRE(db_val.starts_with(db::to_slice(hashed_loc0.bytes)));
            ByteView value{db::from_slice(db_val).substr(kHashLength)};
            REQUIRE(to_hex(value) == to_hex(zeroless_view(new_val.bytes)));

            // location 1
            auto hashed_loc1{keccak256((0x0000000000000000000000000000000000000000000000000000000000000001_bytes32).bytes)};
            hashed_storage_table.to_current_next_multi();
            db_val = hashed_storage_table.current().value;
            CHECK(db_val.starts_with(db::to_slice(hashed_loc1.bytes)));
            value = db::from_slice(db_val).substr(kHashLength);
            // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
            CHECK((to_hex(value) == "01c9"));

            // Unwind the stage to block 1 (i.e. block 1 *is* applied)
            BlockNum unwind_to{1};
            sync_context.unwind_point.emplace(unwind_to);
            actual_stage_result = stage.unwind(txn);
            // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
            REQUIRE((enum_name(actual_stage_result) == enum_name(StageResult::kSuccess)));
            hashed_accounts_table.bind(txn, db::table::kHashedAccounts);
            REQUIRE(hashed_accounts_table.seek(db::to_slice(hashed_sender.bytes)));
            {
                auto account_encoded{db::from_slice(hashed_accounts_table.current().value)};
                auto account{Account::from_encoded_storage(account_encoded)};
                CHECK(account->nonce == 1);
                CHECK(account->balance == kEther);
                CHECK(db::stages::read_stage_progress(txn, db::stages::kHashStateKey) == unwind_to);
            }
        }
    }

    SECTION("Execution and CallTraceIndex") {
        using namespace magic_enum;
        using StageResult = stagedsync::Stage::Result;

        // Prepare block 1
        const auto miner{0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address};
        const auto sender{0x9b9e32061f64f6c3f570a63b97a178d84e961db1_address};
        const auto receiver{miner};

        Block block{};
        block.header.number = 1;
        block.header.beneficiary = receiver;
        block.header.gas_limit = 100'000;
        block.header.gas_used = 21'000;

        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        std::vector<Receipt> receipts{
            {TransactionType::kLegacy, true, block.header.gas_used, {}, {}},
        };
        block.header.receipts_root = trie::root_hash(receipts, kEncoder);

        block.transactions.resize(1);
        block.transactions[0].gas_limit = block.header.gas_limit;
        block.transactions[0].type = TransactionType::kLegacy;

        block.transactions[0].to = miner;
        static_cast<void>(block.transactions[0].set_v(27));
        block.transactions[0].r =
            intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
        block.transactions[0].s =
            intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");
        block.transactions[0].value = 0;

        db::write_header(txn, block.header, /*with_header_numbers=*/true);
        db::write_body(txn, block, block.header.hash(), block.header.number);
        db::write_canonical_header_hash(txn, block.header.hash().bytes, block.header.number);

        // Stage Execution up to block 1
        REQUIRE_NOTHROW(db::stages::write_stage_progress(txn, db::stages::kSendersKey, 1));

        stagedsync::SyncContext sync_context{};
        sync_context.target_height = 1;
        stagedsync::Execution stage_execution = make_execution_stage(&sync_context, node_settings);
        CHECK(stage_execution.forward(txn) == StageResult::kSuccess);

        // Post-condition: CallTraceSet table
        {
            auto call_traces_cursor{txn.ro_cursor(db::table::kCallTraceSet)};
            REQUIRE(call_traces_cursor->size() == 2);
            const auto call_traces_record1{call_traces_cursor->to_next(/*throw_notfound=*/false)};
            REQUIRE(call_traces_record1.done);
            const auto call_traces_record2{call_traces_cursor->to_next(/*throw_notfound=*/false)};
            REQUIRE(call_traces_record2.done);
            auto check_call_trace_record = [&](const auto record, const auto& address, bool is_sender, bool is_receiver) {
                const auto block_number = endian::load_big_u64(static_cast<const uint8_t*>(record.key.data()));
                CHECK(block_number == 1);
                const ByteView value{static_cast<const uint8_t*>(record.value.data()), record.value.length()};
                REQUIRE(value.size() == kAddressLength + 1);
                // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
                CHECK((value.substr(0, kAddressLength) == address));
                CHECK(bool(value[kAddressLength] & 1) == is_sender);
                CHECK(bool(value[kAddressLength] & 2) == is_receiver);
            };
            check_call_trace_record(call_traces_record1, receiver, /*.from=*/false, /*.to=*/true);
            check_call_trace_record(call_traces_record2, sender, /*.from=*/true, /*.to=*/false);
        }

        // Stage CallTraceIndex up to block 1
        stagedsync::CallTraceIndex stage_call_traces = make_call_traces_stage(&sync_context, node_settings);
        REQUIRE(db::stages::read_stage_progress(txn, db::stages::kCallTracesKey) == 0);
        const auto forward_result{stage_call_traces.forward(txn)};
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        CHECK((enum_name(forward_result) == enum_name(StageResult::kSuccess)));
        CHECK(db::stages::read_stage_progress(txn, db::stages::kCallTracesKey) == 1);

        // Post-condition: CallFromIndex table
        {
            auto call_from_cursor{txn.ro_cursor(db::table::kCallFromIndex)};
            REQUIRE(call_from_cursor->size() == 1);
            const auto call_from_record{call_from_cursor->to_next(/*throw_notfound=*/false)};
            REQUIRE(call_from_record.done);
            const auto address_data{db::from_slice(call_from_record.key)};
            REQUIRE(address_data.size() == kAddressLength + sizeof(uint64_t));
            CHECK(bytes_to_address(address_data.substr(0, kAddressLength)) == sender);
            const auto bitmap_encoded{byte_view_to_string_view(db::from_slice(call_from_record.value))};
            const auto bitmap{db::bitmap::parse(bitmap_encoded)};
            CHECK(db::bitmap::seek(bitmap, 1));
        }

        // Post-condition: CallToIndex table
        {
            auto call_to_cursor{txn.ro_cursor(db::table::kCallToIndex)};
            REQUIRE(call_to_cursor->size() == 1);
            const auto call_to_record{call_to_cursor->to_next(/*throw_notfound=*/false)};
            REQUIRE(call_to_record.done);
            const auto address_data{db::from_slice(call_to_record.key)};
            REQUIRE(address_data.size() == kAddressLength + sizeof(uint64_t));
            CHECK(bytes_to_address(address_data.substr(0, kAddressLength)) == receiver);
            const auto bitmap_encoded{byte_view_to_string_view(db::from_slice(call_to_record.value))};
            const auto bitmap{db::bitmap::parse(bitmap_encoded)};
            CHECK(db::bitmap::seek(bitmap, 1));
        }

        // Unwind the stage down to block 0 (i.e. block 0 *is* applied)
        const BlockNum unwind_to{0};
        sync_context.unwind_point.emplace(unwind_to);
        const auto unwind_result{stage_call_traces.unwind(txn)};
        // We need double parentheses here: https://github.com/conan-io/conan-center-index/issues/13993
        CHECK((enum_name(unwind_result) == enum_name(StageResult::kSuccess)));
        CHECK(db::stages::read_stage_progress(txn, db::stages::kCallTracesKey) == unwind_to);
        auto call_from_cursor{txn.ro_cursor(db::table::kCallFromIndex)};
        CHECK(call_from_cursor->empty());
        auto call_to_cursor{txn.ro_cursor(db::table::kCallToIndex)};
        CHECK(call_to_cursor->empty());
    }
}
