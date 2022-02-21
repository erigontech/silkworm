/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "access_layer.hpp"

#include <catch2/catch.hpp>

#include <silkworm/chain/genesis.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

#include "stages.hpp"

namespace silkworm {

static BlockBody sample_block_body() {
    BlockBody body;
    body.transactions.resize(2);

    body.transactions[0].nonce = 172339;
    body.transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    body.transactions[0].max_fee_per_gas = 50 * kGiga;
    body.transactions[0].gas_limit = 90'000;
    body.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    body.transactions[0].value = 1'027'501'080 * kGiga;
    body.transactions[0].data = {};
    CHECK(body.transactions[0].set_v(27));
    body.transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    body.transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    body.transactions[1].type = Transaction::Type::kEip1559;
    body.transactions[1].nonce = 1;
    body.transactions[1].max_priority_fee_per_gas = 5 * kGiga;
    body.transactions[1].max_fee_per_gas = 30 * kGiga;
    body.transactions[1].gas_limit = 1'000'000;
    body.transactions[1].to = {};
    body.transactions[1].value = 0;
    body.transactions[1].data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    CHECK(body.transactions[1].set_v(37));
    body.transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    body.transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    body.ommers.resize(1);
    body.ommers[0].parent_hash = 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32;
    body.ommers[0].ommers_hash = kEmptyListHash;
    body.ommers[0].beneficiary = 0x0c729be7c39543c3d549282a40395299d987cec2_address;
    body.ommers[0].state_root = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;
    body.ommers[0].transactions_root = kEmptyRoot;
    body.ommers[0].receipts_root = kEmptyRoot;
    body.ommers[0].difficulty = 12'555'442'155'599;
    body.ommers[0].number = 13'000'013;
    body.ommers[0].gas_limit = 3'141'592;
    body.ommers[0].gas_used = 0;
    body.ommers[0].timestamp = 1455404305;
    body.ommers[0].mix_hash = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    body.ommers[0].nonce[7] = 35;

    return body;
}

namespace db {

    TEST_CASE("Db Opening") {
        // Empty dir
        std::string empty{};
        db::EnvConfig db_config{empty};
        db_config.inmemory = true;
        REQUIRE_THROWS_AS(db::open_env(db_config), std::invalid_argument);

        // Conflicting flags
        TemporaryDirectory tmp_dir1;
        DataDirectory data_dir{tmp_dir1.path()};
        REQUIRE_NOTHROW(data_dir.deploy());
        REQUIRE(data_dir.exists());

        db_config.path = data_dir.chaindata().path().string();
        db_config.create = true;
        db_config.shared = true;
        REQUIRE_THROWS_AS(db::open_env(db_config), std::runtime_error);

        // Must open
        db_config.shared = false;
        ::mdbx::env_managed env;
        REQUIRE_NOTHROW(env = db::open_env(db_config));

        // Create in same path not allowed
        ::mdbx::env_managed env2;
        REQUIRE_THROWS(env2 = db::open_env(db_config));

        env.close();

        // Conflicting flags
        TemporaryDirectory tmp_dir2;
        db_config = db::EnvConfig{tmp_dir2.path().string()};
        db_config.create = true;
        db_config.readonly = true;
        db_config.inmemory = true;
        REQUIRE_THROWS_AS(db::open_env(db_config), std::runtime_error);

        // Must open
        db_config.readonly = false;
        db_config.exclusive = true;
        REQUIRE_NOTHROW(env = db::open_env(db_config));
        env.close();
    }

    TEST_CASE("Methods cursor_for_each/cursor_for_count") {
        test::Context context;
        auto& txn{context.txn()};

        ::mdbx::map_handle main_map{1};
        auto main_stat{txn.get_map_stat(main_map)};
        auto main_crs{txn.open_cursor(main_map)};
        std::vector<std::string> table_names{};

        const db::WalkFunc walk_func{[&table_names](::mdbx::cursor&, ::mdbx::cursor::move_result& data) -> bool {
            table_names.push_back(data.key.as_string());
            return true;
        }};

        main_crs.to_first();
        db::cursor_for_each(main_crs, walk_func);
        CHECK(table_names.size() == sizeof(db::table::kChainDataTables) / sizeof(db::table::kChainDataTables[0]));
        CHECK(table_names.size() == main_stat.ms_entries);

        main_crs.to_first();
        size_t max_count = table_names.size() - 1;
        table_names.clear();
        db::cursor_for_count(main_crs, walk_func, max_count);
        CHECK(table_names.size() == max_count);
    }

    TEST_CASE("VersionBase primitives") {
        VersionBase v1{0, 0, 0};
        VersionBase v2{0, 0, 1};
        VersionBase v3{0, 0, 1};
        CHECK(v1 != v2);
        CHECK(v2 > v1);
        CHECK(v2 >= v1);
        CHECK(v1 <= v2);
        CHECK(v2 == v3);
    }

    TEST_CASE("Sequences") {
        test::Context context;
        auto& txn{context.txn()};

        auto val1{read_map_sequence(txn, table::kBlockTransactions.name)};
        REQUIRE(val1 == 0);

        auto val2{increment_map_sequence(txn, table::kBlockTransactions.name, 5)};
        REQUIRE(val2 == 0);
        auto val3{read_map_sequence(txn, table::kBlockTransactions.name)};
        REQUIRE((val3 == 5));

        auto val4{increment_map_sequence(txn, table::kBlockTransactions.name, 3)};
        REQUIRE(val4 == 5);
        auto val5{read_map_sequence(txn, table::kBlockTransactions.name)};
        REQUIRE((val5 == 8));

        context.commit_and_renew_txn();
        auto& txn2{context.txn()};

        auto val6{read_map_sequence(txn2, table::kBlockTransactions.name)};
        REQUIRE((val6 == 8));

        // Tamper with sequence
        Bytes fake_value(sizeof(uint32_t), '\0');
        mdbx::slice key(table::kBlockTransactions.name);
        auto tgt{db::open_cursor(txn2, table::kSequence)};
        tgt.upsert(key, to_slice(fake_value));

        bool thrown{false};
        try {
            (void)increment_map_sequence(txn, table::kBlockTransactions.name);
        } catch (const std::exception& ex) {
            REQUIRE(std::string(ex.what()) == "Bad sequence value in db");
            thrown = true;
        }
        REQUIRE(thrown);
    }

    TEST_CASE("Schema Version") {
        test::Context context(/*with_create_tables=*/false);

        SECTION("Read/Write") {
            auto version{db::read_schema_version(context.txn())};
            CHECK(version.has_value() == false);

            version = VersionBase{3, 0, 0};
            CHECK_NOTHROW(db::write_schema_version(context.txn(), version.value()));
            context.commit_and_renew_txn();
            version = db::read_schema_version(context.txn());
            CHECK(version.has_value() == true);

            auto version2{db::read_schema_version(context.txn())};
            CHECK(version.value() == version2.value());

            version2 = VersionBase{2, 0, 0};
            CHECK_THROWS(db::write_schema_version(context.txn(), version2.value()));

            version2 = VersionBase{3, 1, 0};
            CHECK_NOTHROW(db::write_schema_version(context.txn(), version2.value()));
        }

        SECTION("Incompatible schema") {
            // Reduce compat schema version
            auto incompat_version = VersionBase{db::table::kRequiredSchemaVersion.Major - 1, 0, 0};
            REQUIRE_NOTHROW(db::write_schema_version(context.txn(), incompat_version));
            REQUIRE_THROWS(db::table::check_or_create_chaindata_tables(context.txn()));
        }

        SECTION("Incompatible table") {
            (void)context.txn().create_map(db::table::kBlockBodies.name, mdbx::key_mode::reverse,
                                           mdbx::value_mode::multi_reverse);
            REQUIRE_THROWS(db::table::check_or_create_chaindata_tables(context.txn()));
        }
    }

    TEST_CASE("Storage and Prune Modes") {
        test::Context context;
        auto& txn{context.txn()};

        SECTION("Prune Mode") {
            BlockAmount blockAmount;
            REQUIRE(blockAmount.value() == 0);
            REQUIRE(blockAmount.value_from_head(1'000'000) == 0);

            // Uninitialized mode
            PruneMode default_mode{};
            CHECK(default_mode.to_string() == "--prune=");

            // No value in db -> no pruning
            {
                auto prune_mode{db::read_prune_mode(txn)};
                CHECK(prune_mode.to_string() == "--prune=");
                CHECK_NOTHROW(db::write_prune_mode(txn, prune_mode));
                auto db_prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(txn));
                REQUIRE(prune_mode == *db_prune_mode);
            }

            // Cross-check we have the same value
            {
                auto prune_mode = db::read_prune_mode(txn);
                CHECK(prune_mode.to_string() == "--prune=");
            }

            // Write rubbish to prune mode
            {
                auto target{db::open_cursor(txn, table::kDatabaseInfo)};
                std::string db_key{"pruneHistoryType"};
                std::string db_value{"random"};
                target.upsert(mdbx::slice(db_key), mdbx::slice(db_value));
                bool hasThrown{false};
                try {
                    (void)db::read_prune_mode(txn);
                } catch (const std::runtime_error&) {
                    hasThrown = true;
                }
                REQUIRE(hasThrown);
                db_value = "older";
                target.upsert(mdbx::slice(db_key), mdbx::slice(db_value));
            }

            // Provide different combinations of cli arguments
            std::string prune, expected;
            db::PruneDistance olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces;
            db::PruneThreshold beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces;

            prune = "hrstc";
            expected = "--prune=hrstc";
            {
                auto prune_mode =
                    db::parse_prune_mode(prune,  //
                                         olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                         beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE_NOTHROW(db::write_prune_mode(txn, *prune_mode));
                prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(txn));
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE(prune_mode->history().value_from_head(10) == 0);
            }

            prune = "htc";
            olderHistory.emplace(8000);
            olderSenders.emplace(80000);
            beforeReceipts.emplace(10000);
            expected = "--prune=tc --prune.h.older=8000 --prune.r.before=10000 --prune.s.older=80000";
            {
                auto prune_mode =
                    db::parse_prune_mode(prune,  //
                                         olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                         beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE_NOTHROW(db::write_prune_mode(txn, *prune_mode));
                prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(txn));
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE(prune_mode->history() != prune_mode->receipts());
                REQUIRE(prune_mode->tx_index() == prune_mode->call_traces());
            }

            prune = "htc";
            olderHistory.emplace(kFullImmutabilityThreshold);
            olderSenders.reset();
            beforeReceipts.emplace(10000);
            expected = "--prune=htc --prune.r.before=10000";
            {
                auto prune_mode =
                    db::parse_prune_mode(prune,  //
                                         olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                         beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE_NOTHROW(db::write_prune_mode(txn, *prune_mode));
                prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(txn));
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE(prune_mode->receipts().value() == 10000);
                REQUIRE(prune_mode->history().value() == kFullImmutabilityThreshold);
            }

            prune = "hrtc";
            olderHistory.emplace(kFullImmutabilityThreshold + 5);
            beforeReceipts.reset();
            beforeCallTraces.emplace(10000);
            expected = "--prune=rt --prune.h.older=90005 --prune.c.before=10000";
            {
                auto prune_mode =
                    db::parse_prune_mode(prune,  //
                                         olderHistory, olderReceipts, olderSenders, olderTxIndex, olderCallTraces,
                                         beforeHistory, beforeReceipts, beforeSenders, beforeTxIndex, beforeCallTraces);
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE_NOTHROW(db::write_prune_mode(txn, *prune_mode));
                prune_mode = std::make_unique<db::PruneMode>(db::read_prune_mode(txn));
                REQUIRE(prune_mode->to_string() == expected);
                REQUIRE(prune_mode->receipts().value() == kFullImmutabilityThreshold);
                REQUIRE(prune_mode->tx_index().value() == kFullImmutabilityThreshold);
                REQUIRE(prune_mode->call_traces().type() == BlockAmount::Type::kBefore);
                REQUIRE(prune_mode->history().value_from_head(1'000'000) == 909'995);
                REQUIRE(prune_mode->receipts().value_from_head(1'000'000) == 910'000);
                REQUIRE(prune_mode->tx_index().value_from_head(1'000'000) == 910'000);
                REQUIRE(prune_mode->call_traces().type() == BlockAmount::Type::kBefore);
                REQUIRE(prune_mode->call_traces().value_from_head(1'000'000) == 9'999);
            }
        }
    }

    TEST_CASE("read_stages") {
        test::Context context;
        auto& txn{context.txn()};

        // Querying a non-existent stage name should throw
        CHECK_THROWS(stages::read_stage_progress(txn, "NonExistentStage"));
        CHECK_THROWS(stages::read_stage_unwind(txn, "NonExistentStage"));

        // Not valued stage should return 0
        CHECK(stages::read_stage_progress(txn, stages::kBlockBodiesKey) == 0);
        CHECK(stages::read_stage_unwind(txn, stages::kBlockBodiesKey) == 0);

        // Value a stage progress and check returned value
        uint64_t block_num{0};
        uint64_t expected_block_num{123456};
        CHECK_NOTHROW(stages::write_stage_progress(txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(stages::write_stage_unwind(txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(block_num = stages::read_stage_progress(txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(block_num = stages::read_stage_unwind(txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(stages::write_stage_unwind(txn, stages::kBlockBodiesKey));
        CHECK(!stages::read_stage_unwind(txn, stages::kBlockBodiesKey));

        // Write voluntary wrong value in stage
        Bytes stage_progress(2, 0);
        auto map{db::open_cursor(txn, table::kSyncStageProgress)};
        CHECK_NOTHROW(txn.upsert(map, mdbx::slice{stages::kBlockBodiesKey}, to_slice(stage_progress)));
        CHECK_THROWS(block_num = stages::read_stage_progress(txn, stages::kBlockBodiesKey));

        // Check "prune_" prefix
        CHECK_NOTHROW(stages::write_stage_prune_progress(txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(block_num = stages::read_stage_prune_progress(txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(stages::write_stage_prune_progress(txn, stages::kBlockBodiesKey, 0));
        CHECK(stages::read_stage_prune_progress(txn, stages::kBlockBodiesKey) == 0);
    }

    TEST_CASE("read_header") {
        test::Context context;
        auto& txn{context.txn()};

        uint64_t block_num{11'054'435};

        BlockHeader header;
        header.number = block_num;
        header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
        header.gas_limit = 12'451'080;
        header.gas_used = 12'443'619;

        Bytes rlp;
        rlp::encode(rlp, header);
        ethash::hash256 hash{keccak256(rlp)};

        CHECK(!read_header(txn, header.number, hash.bytes));

        // Write canonical header hash + header rlp
        CHECK_NOTHROW(write_canonical_header(txn, header));
        CHECK_NOTHROW(write_header(txn, header, /*with_header_numbers=*/true));

        std::optional<BlockHeader> header_from_db{read_header(txn, header.number, hash.bytes)};
        REQUIRE(header_from_db.has_value());
        CHECK(*header_from_db == header);

        SECTION("read_block") {
            BlockWithHash bh;

            bool read_senders{false};
            CHECK(!read_block(txn, block_num, read_senders, bh));

            BlockBody body{sample_block_body()};
            CHECK_NOTHROW(write_body(txn, body, hash.bytes, header.number));

            REQUIRE(read_block(txn, block_num, read_senders, bh));
            CHECK(bh.block.header == header);
            CHECK(bh.block.ommers == body.ommers);
            CHECK(bh.block.transactions == body.transactions);
            CHECK(ByteView{bh.hash} == ByteView{hash.bytes});

            CHECK(!bh.block.transactions[0].from);
            CHECK(!bh.block.transactions[1].from);

            read_senders = true;
            CHECK_NOTHROW(read_block(txn, block_num, read_senders, bh));

            Bytes full_senders{
                *from_hex("5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c"
                          "941591b6ca8e8dd05c69efdec02b77c72dac1496")};
            REQUIRE(full_senders.length() == 2 * kAddressLength);

            Bytes key{block_key(header.number, hash.bytes)};
            auto sender_table{db::open_cursor(txn, table::kSenders)};
            sender_table.upsert(to_slice(key), to_slice(full_senders));
            REQUIRE(read_block(txn, block_num, read_senders, bh));
            CHECK(bh.block.header == header);
            CHECK(bh.block.ommers == body.ommers);
            CHECK(bh.block.transactions == body.transactions);
            CHECK(ByteView{bh.hash} == ByteView{hash.bytes});

            CHECK(bh.block.transactions[0].from == 0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address);
            CHECK(bh.block.transactions[1].from == 0x941591b6ca8e8dd05c69efdec02b77c72dac1496_address);
        }
    }

    TEST_CASE("read_account") {
        test::Context context;
        auto& txn{context.txn()};

        Buffer buffer{txn, 0};

        const auto miner_a{0x00000000000000000000000000000000000000aa_address};
        const auto miner_b{0x00000000000000000000000000000000000000bb_address};

        Block block1;
        block1.header.number = 1;
        block1.header.beneficiary = miner_a;
        // miner_a gets one block reward
        REQUIRE(execute_block(block1, buffer, kMainnetConfig) == ValidationResult::kOk);

        Block block2;
        block2.header.number = 2;
        block2.header.beneficiary = miner_b;
        // miner_a gets nothing
        REQUIRE(execute_block(block2, buffer, kMainnetConfig) == ValidationResult::kOk);

        Block block3;
        block3.header.number = 3;
        block3.header.beneficiary = miner_a;
        // miner_a gets another block reward
        REQUIRE(execute_block(block3, buffer, kMainnetConfig) == ValidationResult::kOk);

        buffer.write_to_db();

        db::RWTxn tm{txn};
        REQUIRE(stagedsync::stage_account_history(tm, context.dir().etl().path()) == stagedsync::StageResult::kSuccess);

        std::optional<Account> current_account{read_account(txn, miner_a)};
        REQUIRE(current_account.has_value());
        CHECK(current_account->balance == 2 * param::kBlockRewardFrontier);

        std::optional<Account> historical_account{read_account(txn, miner_a, /*block_number=*/2)};
        REQUIRE(historical_account.has_value());
        CHECK(historical_account->balance == param::kBlockRewardFrontier);
    }

    TEST_CASE("read_storage") {
        test::Context context;
        auto& txn{context.txn()};

        auto table{db::open_cursor(txn, table::kPlainState)};

        const auto addr{0xb000000000000000000000000000000000000008_address};
        const Bytes key{storage_prefix(addr, kDefaultIncarnation)};

        const auto loc1{0x000000000000000000000000000000000000a000000000000000000000000037_bytes32};
        const auto loc2{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        const auto loc3{0xff00000000000000000000000000000000000000000000000000000000000017_bytes32};
        const auto loc4{0x00000000000000000000000000000000000000000000000000000000000f3128_bytes32};

        const auto val1{0x00000000000000000000000000000000000000000000000000000000c9b131a4_bytes32};
        const auto val2{0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
        const auto val3{0x4400000000000000000000000000000000000000000000000000000000000000_bytes32};

        upsert_storage_value(table, key, loc1, val1);
        upsert_storage_value(table, key, loc2, val2);
        upsert_storage_value(table, key, loc3, val3);

        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc1) == val1);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc2) == val2);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc3) == val3);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc4) == evmc::bytes32{});
    }

    TEST_CASE("read_account_changes") {
        test::Context context;
        auto& txn{context.txn()};

        uint64_t block_num1{42};
        uint64_t block_num2{49};
        uint64_t block_num3{50};

        AccountChanges changes{read_account_changes(txn, block_num1)};
        CHECK(changes.empty());
        changes = read_account_changes(txn, block_num2);
        CHECK(changes.empty());
        changes = read_account_changes(txn, block_num3);
        CHECK(changes.empty());

        auto addr1{0x63c696931d3d3fd7cd83472febd193488266660d_address};
        auto addr2{0xe439698beccd2acfba60eaa7f7b0b073bcebbdf9_address};
        auto addr3{0x33564393ab248457df0e265107a86bdaf7b1470b_address};
        auto addr4{0xaff7767097705df2dd0cc1c8b69071f6ff044aaa_address};

        const char* val1{"c9b131a4"};
        const char* val2{"076ebaf477f0"};
        const char* val3{""};
        const char* val4{"9a31634956ec64b6865a"};

        auto table{db::open_cursor(txn, table::kAccountChangeSet)};

        Bytes data1{ByteView{addr1}};
        Bytes key1{block_key(block_num1)};
        data1.append(*from_hex(val1));
        table.upsert(to_slice(key1), to_slice(data1));

        Bytes data2{ByteView{addr2}};
        data2.append(*from_hex(val2));
        table.upsert(to_slice(key1), to_slice(data2));

        Bytes data3{ByteView{addr3}};
        data3.append(*from_hex(val3));
        table.upsert(to_slice(key1), to_slice(data3));

        Bytes data4{ByteView{addr4}};
        Bytes key2{block_key(block_num2)};
        data4.append(*from_hex(val4));
        table.upsert(to_slice(key2), to_slice(data4));

        changes = read_account_changes(txn, block_num1);
        REQUIRE(changes.size() == 3);
        CHECK(to_hex(changes[addr1]) == val1);
        CHECK(to_hex(changes[addr2]) == val2);
        CHECK(to_hex(changes[addr3]) == val3);

        changes = read_account_changes(txn, block_num2);
        REQUIRE(changes.size() == 1);
        CHECK(to_hex(changes[addr4]) == val4);

        changes = read_account_changes(txn, block_num3);
        CHECK(changes.empty());
    }

    TEST_CASE("read_storage_changes") {
        test::Context context;
        auto& txn{context.txn()};

        uint64_t block_num1{42};
        uint64_t block_num2{49};
        uint64_t block_num3{50};

        StorageChanges db_changes{read_storage_changes(txn, block_num1)};
        CHECK(db_changes.empty());
        db_changes = read_storage_changes(txn, block_num2);
        CHECK(db_changes.empty());
        db_changes = read_storage_changes(txn, block_num3);
        CHECK(db_changes.empty());

        auto addr1{0x63c696931d3d3fd7cd83472febd193488266660d_address};
        auto addr2{addr1};
        auto addr3{0x33564393ab248457df0e265107a86bdaf7b1470b_address};
        auto addr4{0xaff7767097705df2dd0cc1c8b69071f6ff044aaa_address};

        auto location1{0xb2559376a79a91a99e2a5b644fe9cafdce005b8ad5359c49645ce225e62e6ba5_bytes32};
        auto location2{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        auto location3{0x23d623b732046203836a0ec6666856523b7b3ec4bf4290dd0b544aa6fa5e61ea_bytes32};
        auto location4{0x0000000000000000000000000000000000000000000000000000000000000017_bytes32};

        Bytes val1{*from_hex("c9b131a4")};
        Bytes val2{*from_hex("068566685666856076ebaf477f07")};
        Bytes val3{};
        Bytes val4{*from_hex("9a31634956ec64b6865a")};

        uint64_t incarnation1{1};
        uint64_t incarnation2{1};
        uint64_t incarnation3{3};
        uint64_t incarnation4{1};

        auto table{db::open_cursor(txn, table::kStorageChangeSet)};

        Bytes data1{ByteView{location1}};
        data1.append(val1);
        auto key1{storage_change_key(block_num1, addr1, incarnation1)};
        table.upsert(db::to_slice(key1), db::to_slice(data1));

        Bytes data2{ByteView{location2}};
        data2.append(val2);
        auto key2{storage_change_key(block_num1, addr2, incarnation2)};
        table.upsert(db::to_slice(key2), db::to_slice(data2));

        Bytes data3{ByteView{location3}};
        data3.append(val3);
        auto key3{storage_change_key(block_num1, addr3, incarnation3)};
        table.upsert(db::to_slice(key3), db::to_slice(data3));

        Bytes data4{ByteView{location4}};
        data4.append(val4);
        auto key4{storage_change_key(block_num3, addr4, incarnation4)};
        table.upsert(db::to_slice(key4), db::to_slice(data4));

        CHECK(txn.get_map_stat(table.map()).ms_entries == 4);

        StorageChanges expected_changes1;
        expected_changes1[addr1][incarnation1][location1] = val1;
        expected_changes1[addr2][incarnation2][location2] = val2;
        expected_changes1[addr3][incarnation3][location3] = val3;

        db_changes = read_storage_changes(txn, block_num1);
        CHECK(db_changes.size() == expected_changes1.size());
        CHECK(db_changes == expected_changes1);

        db_changes = read_storage_changes(txn, block_num2);
        CHECK(db_changes.empty());

        StorageChanges expected_changes3;
        expected_changes3[addr4][incarnation4][location4] = val4;

        db_changes = read_storage_changes(txn, block_num3);
        CHECK(db_changes.size() == expected_changes3.size());
        CHECK(db_changes == expected_changes3);
    }

    TEST_CASE("read_chain_config") {
        test::Context context;
        auto& txn{context.txn()};

        const auto chain_config1{read_chain_config(txn)};
        CHECK(chain_config1 == std::nullopt);

        auto canonical_hashes{db::open_cursor(txn, table::kCanonicalHashes)};
        const Bytes genesis_block_key{block_key(0)};
        const auto ropsten_genesis_hash{0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d_bytes32};
        canonical_hashes.upsert(to_slice(genesis_block_key), to_slice(ropsten_genesis_hash));

        const auto chain_config2{read_chain_config(txn)};
        CHECK(chain_config2 == std::nullopt);

        auto config_table{db::open_cursor(txn, table::kConfig)};
        const std::string ropsten_config_json{kRopstenConfig.to_json().dump()};
        config_table.upsert(to_slice(ropsten_genesis_hash), mdbx::slice{ropsten_config_json.c_str()});

        const auto chain_config3{read_chain_config(txn)};
        CHECK(chain_config3 == kRopstenConfig);
    }

    TEST_CASE("Head header") {
        test::Context context;
        auto& txn{context.txn()};

        REQUIRE(db::read_head_header_hash(txn) == std::nullopt);
        const auto ropsten_genesis_hash{0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d_bytes32};
        REQUIRE_NOTHROW(db::write_head_header_hash(txn, ropsten_genesis_hash.bytes));
        REQUIRE(db::read_head_header_hash(txn).value() == ropsten_genesis_hash);
    }

}  // namespace db
}  // namespace silkworm
