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

#include <silkworm/common/chain_genesis.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/buffer.hpp>

#include "stages.hpp"
#include "tables.hpp"

namespace silkworm {

static BlockBody sample_block_body() {
    BlockBody body;
    body.transactions.resize(2);

    body.transactions[0].nonce = 172339;
    body.transactions[0].gas_price = 50 * kGiga;
    body.transactions[0].gas_limit = 90'000;
    body.transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    body.transactions[0].value = 1'027'501'080 * kGiga;
    body.transactions[0].data = {};
    body.transactions[0].set_v(27);
    body.transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    body.transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    body.transactions[1].nonce = 1;
    body.transactions[1].gas_price = 50 * kGiga;
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
    body.ommers[0].number = 1'000'013;
    body.ommers[0].gas_limit = 3'141'592;
    body.ommers[0].gas_used = 0;
    body.ommers[0].timestamp = 1455404305;
    body.ommers[0].mix_hash = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    body.ommers[0].nonce[7] = 35;

    return body;
}

namespace db {

    TEST_CASE("read_stages") {
        TemporaryDirectory tmp_dir;

        lmdb::DatabaseConfig db_config{tmp_dir.path(), 32 * kMebi};
        db_config.set_readonly(false);
        auto env{lmdb::get_env(db_config)};
        auto txn{env->begin_rw_transaction()};
        table::create_all(*txn);

        // Querying an non existent stage name should throe
        CHECK_THROWS(stages::get_stage_progress(*txn, "NonExistentStage"));
        CHECK_THROWS(stages::get_stage_unwind(*txn, "NonExistentStage"));

        // Not valued stage should return 0
        CHECK(stages::get_stage_progress(*txn, stages::kBlockBodiesKey) == 0);
        CHECK(stages::get_stage_unwind(*txn, stages::kBlockBodiesKey) == 0);

        // Value a stage progress and check returned value
        uint64_t block_num{0};
        uint64_t expected_block_num{123456};
        CHECK_NOTHROW(stages::set_stage_progress(*txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(stages::set_stage_unwind(*txn, stages::kBlockBodiesKey, expected_block_num));
        CHECK_NOTHROW(block_num = stages::get_stage_progress(*txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(block_num = stages::get_stage_unwind(*txn, stages::kBlockBodiesKey));
        CHECK(block_num == expected_block_num);
        CHECK_NOTHROW(stages::clear_stage_unwind(*txn, stages::kBlockBodiesKey));
        CHECK(!stages::get_stage_unwind(*txn, stages::kBlockBodiesKey));

        // Write voluntary wrong value in stage
        Bytes stage_progress(2, 0);
        MDB_val mdb_key{std::strlen(stages::kBlockBodiesKey), const_cast<char*>(stages::kBlockBodiesKey)};
        MDB_val mdb_data{db::to_mdb_val(stage_progress)};
        CHECK_NOTHROW(lmdb::err_handler(txn->put(table::kSyncStageProgress, &mdb_key, &mdb_data)));
        CHECK_THROWS(block_num = stages::get_stage_progress(*txn, stages::kBlockBodiesKey));
    }

    TEST_CASE("read_header") {
        TemporaryDirectory tmp_dir;

        lmdb::DatabaseConfig db_config{tmp_dir.path(), 32 * kMebi};
        db_config.set_readonly(false);
        auto env{lmdb::get_env(db_config)};
        auto txn{env->begin_rw_transaction()};
        table::create_all(*txn);

        uint64_t block_num{11'054'435};

        BlockHeader header;
        header.number = block_num;
        header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
        header.gas_limit = 12'451'080;
        header.gas_used = 12'443'619;

        Bytes rlp;
        rlp::encode(rlp, header);
        ethash::hash256 hash{keccak256(rlp)};

        CHECK(!read_header(*txn, header.number, hash.bytes));

        // Write canonical header hash + header rlp
        auto canonical_hashes_table{txn->open(table::kCanonicalHashes)};
        auto k{block_key(block_num)};
        canonical_hashes_table->put(k, Bytes(hash.bytes, kHashLength));

        auto header_table{txn->open(table::kHeaders)};
        Bytes key{block_key(header.number, hash.bytes)};
        header_table->put(key, rlp);

        std::optional<BlockHeader> header_from_db{read_header(*txn, header.number, hash.bytes)};
        REQUIRE(header_from_db);
        CHECK(*header_from_db == header);

        SECTION("read_block") {
            bool read_senders{false};
            CHECK(!read_block(*txn, block_num, read_senders));

            BlockBody body{sample_block_body()};

            detail::BlockBodyForStorage storage_body;
            storage_body.base_txn_id = 1687896;
            storage_body.txn_count = body.transactions.size();
            storage_body.ommers = body.ommers;

            auto body_table{txn->open(table::kBlockBodies)};
            body_table->put(key, storage_body.encode());

            auto txn_table{txn->open(table::kEthTx)};
            Bytes txn_key(8, '\0');
            for (size_t i{0}; i < body.transactions.size(); ++i) {
                boost::endian::store_big_u64(txn_key.data(), storage_body.base_txn_id + i);
                rlp.clear();
                rlp::encode(rlp, body.transactions[i]);
                txn_table->put(txn_key, rlp);
            }

            std::optional<BlockWithHash> bh{read_block(*txn, block_num, read_senders)};
            REQUIRE(bh);
            CHECK(bh->block.header == header);
            CHECK(bh->block.ommers == body.ommers);
            CHECK(bh->block.transactions == body.transactions);
            CHECK(full_view(bh->hash) == full_view(hash.bytes));

            CHECK(!bh->block.transactions[0].from);
            CHECK(!bh->block.transactions[1].from);

            read_senders = true;
            CHECK_THROWS_AS(read_block(*txn, block_num, read_senders), MissingSenders);

            Bytes full_senders{
                *from_hex("5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c"
                          "941591b6ca8e8dd05c69efdec02b77c72dac1496")};
            REQUIRE(full_senders.length() == 2 * kAddressLength);

            ByteView truncated_senders{full_senders.data(), kAddressLength};
            auto sender_table{txn->open(table::kSenders)};
            sender_table->put(key, truncated_senders);
            CHECK_THROWS_AS(read_block(*txn, block_num, read_senders), MissingSenders);

            sender_table->put(key, full_senders);
            bh = read_block(*txn, block_num, read_senders);
            REQUIRE(bh);
            CHECK(bh->block.header == header);
            CHECK(bh->block.ommers == body.ommers);
            CHECK(bh->block.transactions == body.transactions);
            CHECK(full_view(bh->hash) == full_view(hash.bytes));

            CHECK(bh->block.transactions[0].from == 0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address);
            CHECK(bh->block.transactions[1].from == 0x941591b6ca8e8dd05c69efdec02b77c72dac1496_address);
        }
    }

    TEST_CASE("read_account_changes") {
        TemporaryDirectory tmp_dir;

        lmdb::DatabaseConfig db_config{tmp_dir.path(), 32 * kMebi};
        db_config.set_readonly(false);
        auto env{lmdb::get_env(db_config)};
        auto txn{env->begin_rw_transaction()};
        table::create_all(*txn);

        uint64_t block_num1{42};
        uint64_t block_num2{49};
        uint64_t block_num3{50};

        AccountChanges changes{read_account_changes(*txn, block_num1)};
        CHECK(changes.empty());
        changes = read_account_changes(*txn, block_num2);
        CHECK(changes.empty());
        changes = read_account_changes(*txn, block_num3);
        CHECK(changes.empty());

        auto addr1{0x63c696931d3d3fd7cd83472febd193488266660d_address};
        auto addr2{0xe439698beccd2acfba60eaa7f7b0b073bcebbdf9_address};
        auto addr3{0x33564393ab248457df0e265107a86bdaf7b1470b_address};
        auto addr4{0xaff7767097705df2dd0cc1c8b69071f6ff044aaa_address};

        const char* val1{"c9b131a4"};
        const char* val2{"076ebaf477f0"};
        const char* val3{""};
        const char* val4{"9a31634956ec64b6865a"};

        auto table{txn->open(table::kPlainAccountChangeSet)};

        Bytes data1{full_view(addr1)};
        data1.append(*from_hex(val1));
        table->put(block_key(block_num1), data1);

        Bytes data2{full_view(addr2)};
        data2.append(*from_hex(val2));
        table->put(block_key(block_num1), data2);

        Bytes data3{full_view(addr3)};
        data3.append(*from_hex(val3));
        table->put(block_key(block_num1), data3);

        Bytes data4{full_view(addr4)};
        data4.append(*from_hex(val4));
        table->put(block_key(block_num2), data4);

        changes = read_account_changes(*txn, block_num1);
        REQUIRE(changes.size() == 3);
        CHECK(to_hex(changes[addr1]) == val1);
        CHECK(to_hex(changes[addr2]) == val2);
        CHECK(to_hex(changes[addr3]) == val3);

        changes = read_account_changes(*txn, block_num2);
        REQUIRE(changes.size() == 1);
        CHECK(to_hex(changes[addr4]) == val4);

        changes = read_account_changes(*txn, block_num3);
        CHECK(changes.empty());
    }

    TEST_CASE("read_storage_changes") {
        TemporaryDirectory tmp_dir;

        lmdb::DatabaseConfig db_config{tmp_dir.path(), 32 * kMebi};
        db_config.set_readonly(false);
        auto env{lmdb::get_env(db_config)};
        auto txn{env->begin_rw_transaction()};
        table::create_all(*txn);

        uint64_t block_num1{42};
        uint64_t block_num2{49};
        uint64_t block_num3{50};

        StorageChanges db_changes{read_storage_changes(*txn, block_num1)};
        CHECK(db_changes.empty());
        db_changes = read_storage_changes(*txn, block_num2);
        CHECK(db_changes.empty());
        db_changes = read_storage_changes(*txn, block_num3);
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

        auto table{txn->open(table::kPlainStorageChangeSet)};

        Bytes data1{full_view(location1)};
        data1.append(val1);
        table->put(storage_change_key(block_num1, addr1, incarnation1), data1);

        Bytes data2{full_view(location2)};
        data2.append(val2);
        table->put(storage_change_key(block_num1, addr2, incarnation2), data2);

        Bytes data3{full_view(location3)};
        data3.append(val3);
        table->put(storage_change_key(block_num1, addr3, incarnation3), data3);

        Bytes data4{full_view(location4)};
        data4.append(val4);
        table->put(storage_change_key(block_num3, addr4, incarnation4), data4);

        StorageChanges expected_changes1;
        expected_changes1[addr1][incarnation1][location1] = val1;
        expected_changes1[addr2][incarnation2][location2] = val2;
        expected_changes1[addr3][incarnation3][location3] = val3;

        db_changes = read_storage_changes(*txn, block_num1);
        CHECK(db_changes == expected_changes1);

        db_changes = read_storage_changes(*txn, block_num2);
        CHECK(db_changes.empty());

        StorageChanges expected_changes3;
        expected_changes3[addr4][incarnation4][location4] = val4;

        db_changes = read_storage_changes(*txn, block_num3);
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

        lmdb::DatabaseConfig db_config{tmp_dir.path(), 1 * kMebi};
        db_config.set_readonly(false);
        auto env{lmdb::get_env(db_config)};
        auto txn{env->begin_rw_transaction()};
        table::create_all(*txn);

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

        db::Buffer state_buffer(txn.get());
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
        auto noncebe = ethash::be::uint64(nonce); // Swap endianess
        std::memcpy(&header.nonce[0], &noncebe, 8);

        // Verify our RLP encoding produces the same result
        auto computed_hash{header.hash()};
        auto expected_hash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
        CHECK(to_hex(computed_hash) == to_hex(expected_hash));

        // Validate ethash PoW provided nonce and mix_hash
        auto seal_hash(header.hash(/*for_sealing =*/true));
        ethash::hash256 sealh256{};
        std::memcpy(sealh256.bytes, seal_hash.bytes, 32);
        
        auto boundary{ethash::get_boundary_from_diff(header.difficulty)};
        auto epoch_context{ethash::create_epoch_context(0)};
        auto result{ethash::hash(*epoch_context, sealh256, nonce)};

        CHECK(ethash::is_less_or_equal(result.final_hash, boundary));

    }
}  // namespace db
}  // namespace silkworm
