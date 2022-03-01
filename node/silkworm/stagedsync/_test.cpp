/*
    Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/stagedsync/stage_blockhashes.hpp>
#include <silkworm/stagedsync/stage_senders.hpp>
#include <silkworm/stagedsync/stage_execution.hpp>
#include <silkworm/stagedsync/stage_hashstate.hpp>

#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/trie/vector_root.hpp>

using namespace silkworm;
using namespace evmc::literals;

TEST_CASE("Sync Stages") {
    TemporaryDirectory temp_dir{};
    NodeSettings node_settings{};
    node_settings.data_directory = std::make_unique<DataDirectory>(temp_dir.path());
    node_settings.data_directory->deploy();
    node_settings.chaindata_env_config.path = node_settings.data_directory->chaindata().path().string();
    node_settings.chaindata_env_config.max_size = 1_Gibi;      // Small enough to fit in memory
    node_settings.chaindata_env_config.growth_size = 10_Mebi;  // Small increases
    node_settings.chaindata_env_config.inmemory = true;
    node_settings.chaindata_env_config.create = true;
    node_settings.chaindata_env_config.exclusive = true;
    node_settings.prune_mode =
        db::parse_prune_mode("", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                             std::nullopt, std::nullopt, std::nullopt, std::nullopt);

    log::Settings log_settings{};
    log_settings.log_std_out = true;
    log::init(log_settings);

    auto chaindata_env{db::open_env(node_settings.chaindata_env_config)};
    db::RWTxn txn(chaindata_env);
    db::table::check_or_create_chaindata_tables(*txn);
    txn.commit(true);

    auto source_data{read_genesis_data(node_settings.network_id)};
    auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
    db::initialize_genesis(*txn, genesis_json, /*allow_exceptions=*/true);
    txn.commit();
    node_settings.chain_config = db::read_chain_config(*txn);

    SECTION("BlockHashes") {
        std::vector<evmc::bytes32> block_hashes = {
            0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32,
            0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32,
            0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

        auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
        BlockNum block_num{1};
        for (const auto& hash : block_hashes) {
            Bytes block_key{db::block_key(block_num++)};
            canonical_table.insert(db::to_slice(block_key), db::to_slice(hash));
        }
        db::stages::write_stage_progress(*txn, db::stages::kHeadersKey, 3);
        REQUIRE_NOTHROW(txn.commit(true));
        stagedsync::BlockHashes stage(&node_settings);

        // Forward
        auto stage_result{stage.forward(txn)};
        REQUIRE(stage_result == stagedsync::StageResult::kSuccess);
        txn.commit(true);

        {
            // Verify written data is consistent
            auto target_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};
            REQUIRE(txn->get_map_stat(target_table.map()).ms_entries == block_hashes.size() + 1);  // Block 0 is genesis

            std::vector<std::pair<evmc::bytes32, BlockNum>> written_data{};
            db::WalkFunc walk_func = [&written_data](::mdbx::cursor&, ::mdbx::cursor::move_result& data) -> bool {
                auto written_block_num{endian::load_big_u64(static_cast<uint8_t*>(data.value.data()))};
                auto written_hash{to_bytes32(db::from_slice(data.key))};
                written_data.emplace_back(written_hash, written_block_num);
                return true;
            };
            (void)db::cursor_for_each(target_table, walk_func);

            REQUIRE(written_data.size() == block_hashes.size() + 1);
            for (const auto& [written_hash, written_block_num] : written_data) {
                REQUIRE(written_block_num < block_hashes.size() + 1);
                if (written_block_num) {
                    REQUIRE(written_hash == block_hashes.at(written_block_num - 1));
                }
            }
        }

        // Unwind
        stage_result = stage.unwind(txn, 1);
        REQUIRE(stage_result == stagedsync::StageResult::kSuccess);
        {
            // Verify written data is consistent
            auto target_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};
            REQUIRE(txn->get_map_stat(target_table.map()).ms_entries == 2);
            REQUIRE(target_table.seek(db::to_slice(block_hashes.back())) == false);
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
        REQUIRE_NOTHROW(db::write_body(*txn, block_body, block_hashes[0].bytes, 1));

        // Second block - 1 transactions
        REQUIRE_NOTHROW(db::write_body(*txn, block_body, block_hashes[1].bytes, 2));

        // Third block - 0 transactions
        block_body.transactions.clear();
        REQUIRE_NOTHROW(db::write_body(*txn, block_body, block_hashes[2].bytes, 3));

        // Update bodies progress
        REQUIRE_NOTHROW(db::stages::write_stage_progress(*txn, db::stages::kBlockBodiesKey, 3));

        // Write canonical hashes
        REQUIRE_NOTHROW(db::write_canonical_header_hash(*txn, block_hashes[0].bytes, 1));
        REQUIRE_NOTHROW(db::write_canonical_header_hash(*txn, block_hashes[1].bytes, 2));
        REQUIRE_NOTHROW(db::write_canonical_header_hash(*txn, block_hashes[2].bytes, 3));

        // Commit
        REQUIRE_NOTHROW(txn.commit());

        // Verify sequence for transactions has been incremented properly
        auto last_tx_sequence{db::read_map_sequence(*txn, db::table::kBlockTransactions.name)};
        REQUIRE(last_tx_sequence == 2);

        // Check forward works
        stagedsync::Senders stage(&node_settings);
        auto stage_result = stage.forward(txn);
        REQUIRE(stage_result == stagedsync::StageResult::kSuccess);
        REQUIRE_NOTHROW(txn.commit());

        {
            auto senders_map{txn->open_map(db::table::kSenders.name)};
            REQUIRE(txn->get_map_stat(senders_map).ms_entries == 2);

            auto expected_sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};
            auto written_senders{db::read_senders(*txn, 1, block_hashes[0].bytes)};
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(*txn, 2, block_hashes[1].bytes);
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(*txn, 3, block_hashes[2].bytes);
            REQUIRE(written_senders.empty());
        }

        // Check unwind works
        stage_result = stage.unwind(txn, 1);
        REQUIRE(stage_result == stagedsync::StageResult::kSuccess);

        {
            auto senders_map{txn->open_map(db::table::kSenders.name)};
            REQUIRE(txn->get_map_stat(senders_map).ms_entries == 1);

            auto expected_sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};
            auto written_senders{db::read_senders(*txn, 1, block_hashes[0].bytes)};
            REQUIRE(written_senders.size() == 1);
            REQUIRE(written_senders[0] == expected_sender);

            written_senders = db::read_senders(*txn, 2, block_hashes[1].bytes);
            REQUIRE(written_senders.empty());

            written_senders = db::read_senders(*txn, 3, block_hashes[2].bytes);
            REQUIRE(written_senders.empty());
        }

        // TODO(Andrea) Check prune works
    }

    SECTION("Execution and HashState") {
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
            {Transaction::Type::kLegacy, true, block.header.gas_used, {}, {}},
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
        block.transactions[0].type = Transaction::Type::kLegacy;

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
        auto expected_validation_result{magic_enum::enum_name(ValidationResult::kOk)};
        auto actual_validation_result{
            magic_enum::enum_name(execute_block(block, buffer, node_settings.chain_config.value()))};
        REQUIRE(expected_validation_result == actual_validation_result);
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

        actual_validation_result =
            magic_enum::enum_name(execute_block(block, buffer, node_settings.chain_config.value()));
        REQUIRE(expected_validation_result == actual_validation_result);

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

        actual_validation_result =
            magic_enum::enum_name(execute_block(block, buffer, node_settings.chain_config.value()));
        REQUIRE(expected_validation_result == actual_validation_result);
        REQUIRE_NOTHROW(buffer.write_to_db());
        REQUIRE_NOTHROW(db::stages::write_stage_progress(*txn, db::stages::kExecutionKey, 3));
        REQUIRE_NOTHROW(txn.commit());

        SECTION("Execution Unwind") {
            // ---------------------------------------
            // Unwind 3rd block and checks if state is second block
            // ---------------------------------------
            stagedsync::Execution stage(&node_settings);
            REQUIRE(stage.unwind(txn, 2) == stagedsync::StageResult::kSuccess);

            db::Buffer buffer2{*txn, 0};

            std::optional<Account> contract_account{buffer2.read_account(contract_address)};
            REQUIRE(contract_account.has_value());
            CHECK(intx::to_string(contract_account.value().balance) == "1000");  // 2000 - 1000

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
            log::Info() << "Pruning with " << node_settings.prune_mode->to_string();
            stagedsync::Execution stage(&node_settings);
            REQUIRE(stage.prune(txn) == stagedsync::StageResult::kSuccess);

            // With default settings nothing should be pruned
            auto account_changeset_table{db::open_cursor(*txn, db::table::kAccountChangeSet)};
            auto data{account_changeset_table.to_first(false)};
            REQUIRE(data.done);
            BlockNum expected_block_num{0};  // We have account changes from genesis
            auto actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);
            account_changeset_table.close();

            auto storage_changeset_table{db::open_cursor(*txn, db::table::kStorageChangeSet)};
            data = storage_changeset_table.to_first(false);
            REQUIRE(data.done);
            expected_block_num = 1;  // First storage change is at block 1
            actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);
            storage_changeset_table.close();
            REQUIRE(db::stages::read_stage_prune_progress(*txn, db::stages::kExecutionKey) == 3);
        }

        SECTION("Execution Prune History") {
            // Override prune mode and issue pruning
            node_settings.prune_mode =
                db::parse_prune_mode("", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, 2,
                                     std::nullopt, std::nullopt, std::nullopt, std::nullopt);

            log::Info() << "Pruning with " << node_settings.prune_mode->to_string();
            REQUIRE(node_settings.prune_mode->history().enabled());
            stagedsync::Execution stage(&node_settings);
            REQUIRE(stage.prune(txn) == stagedsync::StageResult::kSuccess);

            auto account_changeset_table{db::open_cursor(*txn, db::table::kAccountChangeSet)};
            auto data{account_changeset_table.to_first(false)};
            REQUIRE(data.done);
            BlockNum expected_block_num = 2;  // We've pruned history *before* 2 so the last is 2
            BlockNum actual_block_num = endian::load_big_u64(db::from_slice(data.key).data());
            REQUIRE(actual_block_num == expected_block_num);
            account_changeset_table.close();
            REQUIRE(db::stages::read_stage_prune_progress(*txn, db::stages::kExecutionKey) == 3);
        }

        SECTION("HashState") {
            stagedsync::HashState stage(&node_settings);
            auto expected_stage_result{
                magic_enum::enum_name<stagedsync::StageResult>(stagedsync::StageResult::kSuccess)};
            auto actual_stage_result = magic_enum::enum_name<stagedsync::StageResult>(stage.forward(txn));
            REQUIRE(expected_stage_result == actual_stage_result);
            REQUIRE(db::stages::read_stage_progress(*txn, db::stages::kHashStateKey) == 3);

            // ---------------------------------------
            // Check hashed account
            // ---------------------------------------
            auto hashed_accounts_table{db::open_cursor(*txn, db::table::kHashedAccounts)};
            auto hashed_sender{keccak256(sender)};
            REQUIRE(hashed_accounts_table.seek(db::to_slice(hashed_sender.bytes)));
            {
                auto account_encoded{db::from_slice(hashed_accounts_table.current().value)};
                auto [account, _]{Account::from_encoded_storage(account_encoded)};
                CHECK(account.nonce == 3);
                CHECK(account.balance < kEther);
            }

            // ---------------------------------------
            // Check hashed storage
            // ---------------------------------------
            auto hashed_storage_table{db::open_cursor(*txn, db::table::kHashedStorage)};
            auto hashed_contract{keccak256(contract_address)};
            Bytes storage_key{db::storage_prefix(hashed_contract.bytes, kDefaultIncarnation)};
            REQUIRE(hashed_storage_table.find(db::to_slice(storage_key)));
            REQUIRE(hashed_storage_table.count_multivalue() == 2);

            // location 0
            auto hashed_loc0{keccak256(0x0000000000000000000000000000000000000000000000000000000000000000_bytes32)};
            hashed_storage_table.to_current_first_multi();
            mdbx::slice db_val{hashed_storage_table.current().value};
            REQUIRE(db_val.starts_with(db::to_slice(hashed_loc0.bytes)));
            ByteView value{db::from_slice(db_val).substr(kHashLength)};
            REQUIRE(to_hex(value) == to_hex(zeroless_view(new_val)));

            // location 1
            auto hashed_loc1{keccak256(0x0000000000000000000000000000000000000000000000000000000000000001_bytes32)};
            hashed_storage_table.to_current_next_multi();
            db_val = hashed_storage_table.current().value;
            CHECK(db_val.starts_with(db::to_slice(hashed_loc1.bytes)));
            value = db::from_slice(db_val).substr(kHashLength);
            CHECK(to_hex(value) == "01c9");

            // Unwind the stage to block 1 (i.e. block 1 *is* applied)
            BlockNum unwind_to{1};
            actual_stage_result = magic_enum::enum_name<stagedsync::StageResult>(stage.unwind(txn, unwind_to));
            REQUIRE(expected_stage_result == actual_stage_result);
            hashed_accounts_table = db::open_cursor(*txn, db::table::kHashedAccounts);
            REQUIRE(hashed_accounts_table.seek(db::to_slice(hashed_sender.bytes)));
            {
                auto account_encoded{db::from_slice(hashed_accounts_table.current().value)};
                auto [account, _]{Account::from_encoded_storage(account_encoded)};
                CHECK(account.nonce == 1);
                CHECK(account.balance == kEther);
                CHECK(db::stages::read_stage_progress(*txn, db::stages::kHashStateKey) == unwind_to);
            }
        }
    }
}