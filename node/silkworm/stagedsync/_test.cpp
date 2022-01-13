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

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/settings.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/genesis.hpp>
#include <silkworm/stagedsync/common.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

#include "silkworm/chain/genesis.hpp"

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
            db::cursor_for_each(
                target_table, [&written_data](::mdbx::cursor&, ::mdbx::cursor::move_result& data) -> bool {
                    auto written_block_num{endian::load_big_u64(static_cast<uint8_t*>(data.value.data()))};
                    auto written_hash{to_bytes32(db::from_slice(data.key))};
                    written_data.emplace_back(written_hash, written_block_num);
                    return true;
                });

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
}