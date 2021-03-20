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

#include <silkworm/common/temp_dir.hpp>

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

            header_table->put(block_key(block_num), full_view(hash.bytes));
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
}  // namespace db
}  // namespace silkworm
