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

#include "access_layer.hpp"

#include <boost/endian/conversion.hpp>
#include <catch2/catch.hpp>
#include <ethash/ethash.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/chain_genesis.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/stagedsync/stagedsync.hpp>

#include "bitmap.hpp"
#include "stages.hpp"
#include "tables.hpp"

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
    body.transactions[0].set_v(27);
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
    body.transactions[1].set_v(37);
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
        DataDirectory data_dir{std::string(tmp_dir1.path())};
        REQUIRE_NOTHROW(data_dir.create_tree());
        REQUIRE(std::filesystem::exists(data_dir.get_chaindata_path()));

        db_config.path = data_dir.get_chaindata_path().string();
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
        db_config = db::EnvConfig{tmp_dir2.path()};
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

    TEST_CASE("Methods for_each/for_count") {
        TemporaryDirectory tmp_dir;
        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        ::mdbx::map_handle main_map{1};
        auto main_stat{txn.get_map_stat(main_map)};
        auto main_crs{txn.open_cursor(main_map)};
        std::vector<std::string> table_names{};

        const auto& walk_func{[&table_names](::mdbx::cursor::move_result data) -> bool {
            table_names.push_back(data.key.as_string());
            return true;
        }};

        main_crs.to_first();
        db::for_each(main_crs, walk_func);
        CHECK(table_names.size() == sizeof(db::table::kTables) / sizeof(db::table::kTables[0]));
        CHECK(table_names.size() == main_stat.ms_entries);

        main_crs.to_first();
        size_t max_count = table_names.size() - 1;
        table_names.clear();
        db::for_count(main_crs, walk_func, max_count);
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

    TEST_CASE("Read schema Version") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        auto version{db::read_schema_version(txn)};
        CHECK(version.has_value() == false);

        version = VersionBase{3, 0, 0};
        CHECK_NOTHROW(db::write_schema_version(txn, version.value()));
        version = db::read_schema_version(txn);
        CHECK(version.has_value() == true);

        CHECK_NOTHROW(txn.commit());
        txn = env.start_write();

        auto version2{db::read_schema_version(txn)};
        CHECK(version.value() == version2.value());

        version2 = VersionBase{2, 0, 0};
        CHECK_THROWS(db::write_schema_version(txn, version2.value()));

        version2 = VersionBase{3, 1, 0};
        CHECK_NOTHROW(db::write_schema_version(txn, version2.value()));
    }

    TEST_CASE("Storage Mode") {
        TemporaryDirectory tmp_dir;
        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        StorageMode default_mode{};
        CHECK(default_mode.to_string() == "default");

        StorageMode expected_mode{true, false, false, false, false, false};
        auto actual_mode{db::read_storage_mode(txn)};
        CHECK(expected_mode == actual_mode);

        std::string mode_s1{};
        auto actual_mode1{db::parse_storage_mode(mode_s1)};
        CHECK(actual_mode1.to_string() == mode_s1);

        std::string mode_s2{"default"};
        auto actual_mode2{db::parse_storage_mode(mode_s2)};
        CHECK(actual_mode2.to_string() == kDefaultStorageMode.to_string());

        std::string mode_s3{"x"};
        CHECK_THROWS(db::parse_storage_mode(mode_s3));

        std::string mode_s4{"hrc"};
        auto actual_mode4{db::parse_storage_mode(mode_s4)};
        CHECK(actual_mode4.to_string() == mode_s4);

        db::write_storage_mode(txn, actual_mode4);
        CHECK_NOTHROW(txn.commit());

        txn = env.start_read();
        auto actual_mode5{db::read_storage_mode(txn)};
        CHECK(actual_mode4.to_string() == actual_mode5.to_string());

        std::string mode_s6{"hrtce"};
        auto actual_mode6{db::parse_storage_mode(mode_s6)};
        CHECK(actual_mode6.to_string() == mode_s6);
    }

    TEST_CASE("read_stages") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        // Querying an non existent stage name should throe
        CHECK_THROWS(stages::get_stage_progress(txn, "NonExistentStage"));
        CHECK_THROWS(stages::get_stage_unwind(txn, "NonExistentStage"));

        // Not valued stage should return 0
        CHECK(stages::get_stage_progress(txn, stages::kBlockBodiesKey) == 0);
        CHECK(stages::get_stage_unwind(txn, stages::kBlockBodiesKey) == 0);

        // Value a stage progress and check returned value
        uint64_t block_num{0};
        uint64_t expected_block_num{123456};
        CHECK_NOTHROW(stages::set_stage_progress(txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(stages::set_stage_unwind(txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(block_num = stages::get_stage_progress(txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(block_num = stages::get_stage_unwind(txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(stages::clear_stage_unwind(txn, stages::kBlockBodiesKey));
        CHECK(!stages::get_stage_unwind(txn, stages::kBlockBodiesKey));

        // Write voluntary wrong value in stage
        Bytes stage_progress(2, 0);
        auto key{byte_view_of_c_str(stages::kBlockBodiesKey)};
        auto map{db::open_cursor(txn, table::kSyncStageProgress)};
        CHECK_NOTHROW(txn.upsert(map, to_slice(key), to_slice(stage_progress)));
        CHECK_THROWS(block_num = stages::get_stage_progress(txn, stages::kBlockBodiesKey));
    }

    TEST_CASE("read_header") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

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
        auto canonical_hashes_table{db::open_cursor(txn, table::kCanonicalHashes)};
        auto k{block_key(block_num)};
        Bytes v(hash.bytes, kHashLength);
        canonical_hashes_table.upsert(to_slice(k), to_slice(v));

        auto header_table{db::open_cursor(txn, table::kHeaders)};
        Bytes key{block_key(header.number, hash.bytes)};
        header_table.upsert(to_slice(key), to_slice(rlp));

        std::optional<BlockHeader> header_from_db{read_header(txn, header.number, hash.bytes)};
        REQUIRE(header_from_db);
        CHECK(*header_from_db == header);

        SECTION("read_block") {
            bool read_senders{false};
            CHECK(!read_block(txn, block_num, read_senders));

            BlockBody body{sample_block_body()};

            detail::BlockBodyForStorage storage_body;
            storage_body.base_txn_id = 1687896;
            storage_body.txn_count = body.transactions.size();
            storage_body.ommers = body.ommers;

            auto body_table{db::open_cursor(txn, table::kBlockBodies)};
            auto body_data{storage_body.encode()};
            body_table.upsert(to_slice(key), to_slice(body_data));

            auto txn_table{db::open_cursor(txn, table::kEthTx)};
            Bytes txn_key(8, '\0');
            for (size_t i{0}; i < body.transactions.size(); ++i) {
                boost::endian::store_big_u64(txn_key.data(), storage_body.base_txn_id + i);
                rlp.clear();
                rlp::encode(rlp, body.transactions[i]);
                txn_table.upsert(to_slice(txn_key), to_slice(rlp));
            }

            std::optional<BlockWithHash> bh{read_block(txn, block_num, read_senders)};
            REQUIRE(bh);
            CHECK(bh->block.header == header);
            CHECK(bh->block.ommers == body.ommers);
            CHECK(bh->block.transactions == body.transactions);
            CHECK(full_view(bh->hash) == full_view(hash.bytes));

            CHECK(!bh->block.transactions[0].from);
            CHECK(!bh->block.transactions[1].from);

            read_senders = true;
            CHECK_THROWS_AS(read_block(txn, block_num, read_senders), MissingSenders);

            Bytes full_senders{
                *from_hex("5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c"
                          "941591b6ca8e8dd05c69efdec02b77c72dac1496")};
            REQUIRE(full_senders.length() == 2 * kAddressLength);

            ByteView truncated_senders{full_senders.data(), kAddressLength};
            auto sender_table{db::open_cursor(txn, table::kSenders)};
            sender_table.upsert(to_slice(key), to_slice(truncated_senders));
            CHECK_THROWS_AS(read_block(txn, block_num, read_senders), MissingSenders);

            sender_table.upsert(to_slice(key), to_slice(full_senders));
            bh = read_block(txn, block_num, read_senders);
            REQUIRE(bh);
            CHECK(bh->block.header == header);
            CHECK(bh->block.ommers == body.ommers);
            CHECK(bh->block.transactions == body.transactions);
            CHECK(full_view(bh->hash) == full_view(hash.bytes));

            CHECK(bh->block.transactions[0].from == 0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address);
            CHECK(bh->block.transactions[1].from == 0x941591b6ca8e8dd05c69efdec02b77c72dac1496_address);
        }
    }

    TEST_CASE("read_account") {
        TemporaryDirectory tmp_dir;
        DataDirectory data_dir{tmp_dir.path(), /*create=*/true};
        EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
        db_config.inmemory = true;
        auto env{open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        Buffer buffer{txn};
        std::vector<Receipt> receipts;

        const auto miner_a{0x00000000000000000000000000000000000000aa_address};
        const auto miner_b{0x00000000000000000000000000000000000000bb_address};

        Block block1;
        block1.header.number = 1;
        block1.header.beneficiary = miner_a;
        // miner_a gets one block reward
        REQUIRE(execute_block(block1, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);

        Block block2;
        block2.header.number = 2;
        block2.header.beneficiary = miner_b;
        // miner_a gets nothing
        REQUIRE(execute_block(block2, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);

        Block block3;
        block3.header.number = 3;
        block3.header.beneficiary = miner_a;
        // miner_a gets another block reward
        REQUIRE(execute_block(block3, buffer, kMainnetConfig, receipts) == ValidationResult::kOk);

        buffer.write_to_db();

        stagedsync::TransactionManager tm{txn};
        REQUIRE(stagedsync::stage_account_history(tm, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);

        std::optional<Account> current_account{read_account(txn, miner_a)};
        REQUIRE(current_account.has_value());
        CHECK(current_account->balance == 2 * param::kBlockRewardFrontier);

        std::optional<Account> historical_account{read_account(txn, miner_a, /*block_number=*/2)};
        REQUIRE(historical_account.has_value());
        CHECK(historical_account->balance == param::kBlockRewardFrontier);
    }

    TEST_CASE("read_storage") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        auto table{db::open_cursor(txn, table::kPlainState)};

        const auto addr{0xb000000000000000000000000000000000000008_address};
        const Bytes key{storage_prefix(full_view(addr), kDefaultIncarnation)};

        const auto loc1{0x000000000000000000000000000000000000a000000000000000000000000037_bytes32};
        const auto loc2{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
        const auto loc3{0xff00000000000000000000000000000000000000000000000000000000000017_bytes32};
        const auto loc4{0x00000000000000000000000000000000000000000000000000000000000f3128_bytes32};

        const auto val1{0x00000000000000000000000000000000000000000000000000000000c9b131a4_bytes32};
        const auto val2{0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
        const auto val3{0x4400000000000000000000000000000000000000000000000000000000000000_bytes32};

        Bytes dat1{full_view(loc1)};
        dat1.append(zeroless_view(val1));
        table.upsert(to_slice(key), to_slice(dat1));

        Bytes dat2{full_view(loc2)};
        dat2.append(zeroless_view(val2));
        table.upsert(to_slice(key), to_slice(dat2));

        Bytes dat3{full_view(loc3)};
        dat3.append(zeroless_view(val3));
        table.upsert(to_slice(key), to_slice(dat3));

        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc1) == val1);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc2) == val2);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc3) == val3);
        CHECK(db::read_storage(txn, addr, kDefaultIncarnation, loc4) == evmc::bytes32{});
    }

    TEST_CASE("read_account_changes") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

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

        auto table{db::open_cursor(txn, table::kPlainAccountChangeSet)};

        Bytes data1{full_view(addr1)};
        Bytes key1{block_key(block_num1)};
        data1.append(*from_hex(val1));
        table.upsert(to_slice(key1), to_slice(data1));

        Bytes data2{full_view(addr2)};
        data2.append(*from_hex(val2));
        table.upsert(to_slice(key1), to_slice(data2));

        Bytes data3{full_view(addr3)};
        data3.append(*from_hex(val3));
        table.upsert(to_slice(key1), to_slice(data3));

        Bytes data4{full_view(addr4)};
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
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

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

        auto table{db::open_cursor(txn, table::kPlainStorageChangeSet)};

        Bytes data1{full_view(location1)};
        data1.append(val1);
        auto key1{storage_change_key(block_num1, addr1, incarnation1)};
        table.upsert(db::to_slice(key1), db::to_slice(data1));

        Bytes data2{full_view(location2)};
        data2.append(val2);
        auto key2{storage_change_key(block_num1, addr2, incarnation2)};
        table.upsert(db::to_slice(key2), db::to_slice(data2));

        Bytes data3{full_view(location3)};
        data3.append(val3);
        auto key3{storage_change_key(block_num1, addr3, incarnation3)};
        table.upsert(db::to_slice(key3), db::to_slice(data3));

        Bytes data4{full_view(location4)};
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

    TEST_CASE("genesis config") {
        std::string source_genesis(genesis_mainnet_data(), sizeof_genesis_mainnet_data());

        auto genesis_json = nlohmann::json::parse(source_genesis, nullptr, /* allow_exceptions = */ false);
        CHECK(genesis_json != nlohmann::json::value_t::discarded);
        CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
        auto config = ChainConfig::from_json(genesis_json["config"]);
        CHECK(config.has_value());
        CHECK(config.value() == kMainnetConfig);

        source_genesis.assign(genesis_goerli_data(), sizeof_genesis_goerli_data());

        genesis_json = nlohmann::json::parse(source_genesis, nullptr, /* allow_exceptions = */ false);
        CHECK(genesis_json != nlohmann::json::value_t::discarded);
        CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
        config = ChainConfig::from_json(genesis_json["config"]);
        CHECK(config.has_value());
        CHECK(config.value() == kGoerliConfig);

        source_genesis.assign(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());

        genesis_json = nlohmann::json::parse(source_genesis, nullptr, /* allow_exceptions = */ false);
        CHECK(genesis_json != nlohmann::json::value_t::discarded);
        CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
        config = ChainConfig::from_json(genesis_json["config"]);
        CHECK(config.has_value());
        CHECK(config.value() == kRinkebyConfig);
    }

    TEST_CASE("mainnet_genesis") {
        TemporaryDirectory tmp_dir;

        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

        // Parse genesis data
        std::string source_data;
        source_data.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
        auto genesis_json = nlohmann::json::parse(source_data, nullptr, /* allow_exceptions = */ false);
        CHECK(genesis_json != nlohmann::json::value_t::discarded);

        CHECK(genesis_json.contains("difficulty"));
        CHECK(genesis_json.contains("nonce"));
        CHECK(genesis_json.contains("gasLimit"));
        CHECK(genesis_json.contains("timestamp"));
        CHECK(genesis_json.contains("extraData"));
        CHECK((genesis_json.contains("alloc") && genesis_json["alloc"].is_object() && genesis_json["alloc"].size()));

        db::Buffer state_buffer(txn);
        size_t expected_allocations{genesis_json["alloc"].size()};

        for (auto& item : genesis_json["alloc"].items()) {
            if (!item.value().is_object() || !item.value().contains("balance") ||
                !item.value()["balance"].is_string()) {
                throw std::invalid_argument("alloc address " + item.key() + " has badly formatted allocation");
            }

            auto address_bytes{from_hex(item.key())};
            if (address_bytes == std::nullopt || address_bytes.value().length() != kAddressLength) {
                throw std::invalid_argument("alloc address " + item.key() + " is not valid. Either not hex or not " +
                                            std::to_string(kAddressLength) + " bytes");
            }

            evmc::address account_address = to_address(*address_bytes);
            auto balance_str{item.value()["balance"].get<std::string>()};
            Account account{0, intx::from_string<intx::uint256>(balance_str)};
            state_buffer.update_account(account_address, std::nullopt, account);
        }

        auto applied_allocations{static_cast<size_t>(state_buffer.account_changes().at(0).size())};
        CHECK(applied_allocations == expected_allocations);

        SECTION("state_root") {
            auto expected_state_root{0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544_bytes32};
            auto actual_state_root{state_buffer.state_root_hash()};
            auto a = full_view(expected_state_root);
            auto b = full_view(actual_state_root);
            CHECK(to_hex(a) == to_hex(b));
        }

        // Fill Header
        BlockHeader header;
        auto parent_hash{from_hex(genesis_json["parentHash"].get<std::string>())};
        if (parent_hash.has_value()) {
            header.parent_hash = to_bytes32(*parent_hash);
        }
        header.ommers_hash = kEmptyListHash;
        header.beneficiary = 0x0000000000000000000000000000000000000000_address;
        header.state_root = state_buffer.state_root_hash();
        header.transactions_root = kEmptyRoot;
        header.receipts_root = kEmptyRoot;
        auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
        header.number = 0;
        header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>().c_str(), nullptr, 0);
        header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>().c_str(), nullptr, 0);

        auto extra_data = from_hex(genesis_json["extraData"].get<std::string>());
        if (extra_data.has_value()) {
            header.extra_data = *extra_data;
        }

        auto mix_data = from_hex(genesis_json["mixhash"].get<std::string>());
        CHECK((mix_data.has_value() && mix_data->size() == kHashLength));
        header.mix_hash = to_bytes32(*mix_data);

        auto nonce = std::stoull(genesis_json["nonce"].get<std::string>().c_str(), nullptr, 0);
        boost::endian::store_big_u64(header.nonce.data(), nonce);

        // Verify our RLP encoding produces the same result
        auto computed_hash{header.hash()};
        auto expected_hash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
        CHECK(to_hex(computed_hash) == to_hex(expected_hash));

        // TODO (Andrea) Why this fails for genesis ?
        // auto seal_hash(header.hash(/*for_sealing =*/true));
        // ethash::hash256 sealh256{};
        // std::memcpy(sealh256.bytes, seal_hash.bytes, 32);
        // auto boundary{ethash::get_boundary_from_diff(header.difficulty)};
        // auto epoch_context{ethash::create_epoch_context(0)};
        // auto result{ethash::hash(*epoch_context, sealh256, nonce)};
        // CHECK(ethash::is_less_or_equal(result.final_hash, boundary));
    }

    TEST_CASE("read_chain_config") {
        TemporaryDirectory tmp_dir;
        db::EnvConfig db_config{tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;
        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};
        table::create_all(txn);

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
        config_table.upsert(to_slice(ropsten_genesis_hash), to_slice(byte_view_of_c_str(ropsten_config_json.c_str())));

        const auto chain_config3{read_chain_config(txn)};
        CHECK(chain_config3 == kRopstenConfig);
    }

}  // namespace db
}  // namespace silkworm
