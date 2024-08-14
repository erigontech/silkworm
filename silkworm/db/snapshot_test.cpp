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

#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/bodies/body_queries.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/headers/header_queries.hpp>
#include <silkworm/db/snapshots/index_builder.hpp>
#include <silkworm/db/snapshots/snapshot_reader.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_queries.hpp>
#include <silkworm/db/transactions/txn_snapshot_word_serializer.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

namespace test = test_util;
using silkworm::test_util::SetLogVerbosityGuard;

static const SnapshotPath kValidHeadersSegmentPath{*SnapshotPath::parse("v1-014500-015000-headers.seg")};

class SnapshotPath_ForTest : public SnapshotPath {
  public:
    SnapshotPath_ForTest(const std::filesystem::path& tmp_dir, BlockNum block_from, BlockNum block_to)
        : SnapshotPath(SnapshotPath::from(tmp_dir,
                                          kSnapshotV1,
                                          block_from,
                                          block_to,
                                          SnapshotType::headers)) {}
};

class Snapshot_ForTest : public Snapshot {
  public:
    explicit Snapshot_ForTest(SnapshotPath path) : Snapshot(std::move(path)) {}
    explicit Snapshot_ForTest(std::filesystem::path path) : Snapshot(*SnapshotPath::parse(std::move(path))) {}
    Snapshot_ForTest(const std::filesystem::path& tmp_dir, BlockNum block_from, BlockNum block_to)
        : Snapshot(SnapshotPath_ForTest{tmp_dir, block_from, block_to}) {}
};

TEST_CASE("Snapshot::Snapshot", "[silkworm][node][snapshot][snapshot]") {
    TemporaryDirectory tmp_dir;
    SECTION("valid") {
        std::vector<std::pair<BlockNum, BlockNum>> block_ranges{
            {0, 1},
            {1'000, 1'000},
            {1'000, 2'000}};
        for (const auto& [block_from, block_to] : block_ranges) {
            Snapshot_ForTest snapshot{tmp_dir.path(), block_from, block_to};
            CHECK(!snapshot.fs_path().empty());
            CHECK(snapshot.block_from() == block_from);
            CHECK(snapshot.block_to() == block_to);
            CHECK(snapshot.item_count() == 0);
            CHECK(snapshot.empty());
        }
    }
    SECTION("invalid") {
        std::vector<std::pair<BlockNum, BlockNum>> block_ranges{
            {1'000, 999}};
        for (const auto& [block_from, block_to] : block_ranges) {
            CHECK_THROWS_AS(Snapshot_ForTest(tmp_dir.path(), block_from, block_to), std::logic_error);
        }
    }
}

TEST_CASE("Snapshot::reopen_segment", "[silkworm][node][snapshot][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::TemporarySnapshotFile tmp_snapshot_file{tmp_dir.path(), kValidHeadersSegmentPath.filename(), test::SnapshotHeader{}};
    Snapshot_ForTest snapshot{tmp_snapshot_file.path()};
    snapshot.reopen_segment();
}

TEST_CASE("Snapshot::for_each_item", "[silkworm][node][snapshot][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::HelloWorldSnapshotFile hello_world_snapshot_file{tmp_dir.path(), kValidHeadersSegmentPath.filename()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path()};
    tmp_snapshot.reopen_segment();
    CHECK(!tmp_snapshot.empty());
    CHECK(tmp_snapshot.item_count() == 1);

    seg::Decompressor decoder{hello_world_snapshot_file.path()};
    decoder.open();
    auto it = decoder.begin();
    auto& word = *it;
    CHECK(std::string{word.cbegin(), word.cend()} == "hello, world");
    CHECK(it.current_word_offset() == 0);
    CHECK(++it == decoder.end());
}

TEST_CASE("Snapshot::close", "[silkworm][node][snapshot][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::HelloWorldSnapshotFile hello_world_snapshot_file{tmp_dir.path(), kValidHeadersSegmentPath.filename()};
    seg::Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path()};
    tmp_snapshot.reopen_segment();
    CHECK_NOTHROW(tmp_snapshot.close());
}

// https://etherscan.io/block/1500013
TEST_CASE("HeaderSnapshot::header_by_number OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleHeaderSnapshotFile valid_header_snapshot{tmp_dir.path()};               // contains headers for [1'500'012, 1'500'013]
    test::SampleHeaderSnapshotPath header_snapshot_path{valid_header_snapshot.path()};  // necessary to tweak the block numbers
    auto header_index = HeaderIndex::make(header_snapshot_path);
    REQUIRE_NOTHROW(header_index.build());

    Snapshot header_snapshot{header_snapshot_path};
    header_snapshot.reopen_segment();

    Index idx_header_hash{header_snapshot_path.index_file()};
    idx_header_hash.reopen_index();
    HeaderFindByBlockNumQuery header_by_number{{header_snapshot, idx_header_hash}};

    CHECK(!header_by_number.exec(1'500'011));
    CHECK(header_by_number.exec(1'500'012));
    const auto header = header_by_number.exec(1'500'013);
    CHECK(header.has_value());
    if (header) {
        CHECK(header->hash() == 0xbef48d7de01f2d7ea1a7e4d1ed401f73d6d0257a364f6770b25ba51a123ac35f_bytes32);
        CHECK(header->parent_hash == 0x48a486d69a07e99ed6997eb0f9b8795e4e7d07c0ce5b8ee8e139d653fd1b01c3_bytes32);
        CHECK(header->ommers_hash == 0x7117cfc18ff9765fb04a0c223722d1cfd20a06e5d7a88778f9f66a2207b0638b_bytes32);
        CHECK(header->beneficiary == 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address);
        CHECK(header->state_root == 0xac26fc90b79cd9304f03c925208e377d4e6e4b229ede56eb1728851e656791bc_bytes32);
        CHECK(header->transactions_root == 0xbc18a809c2ab84e0870c0be8de331e3e0498e31b22cdeb95e07f23a5c7f77f40_bytes32);
        CHECK(header->receipts_root == 0xc856db90a6c30a0264858960231c4a3f78f557ea83ea4d7ec260c691b0850523_bytes32);
        CHECK(header->logs_bloom == Bloom{});
        CHECK(header->difficulty == 0x1fad3d458f3e);
        CHECK(header->number == 1'500'013);
        CHECK(header->gas_limit == 4'712'388);

        CHECK(header->gas_used == 21'000);
        CHECK(header->timestamp == 1463003399);
        CHECK(header->extra_data == *from_hex("0xd783010400844765746887676f312e352e31856c696e7578"));
        CHECK(header->prev_randao == 0x799895e28a837bbdf28b8ecf5fc0e6251398ecb0ffc7ff5bbb457c21b14ce982_bytes32);
        CHECK(header->nonce == std::array<uint8_t, 8>{0x86, 0x98, 0x76, 0x20, 0x12, 0xb4, 0x6f, 0xef});
    }
    CHECK(!header_by_number.exec(1'500'014));
}

// https://etherscan.io/block/1500013
TEST_CASE("BodySnapshot::body_by_number OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile valid_body_snapshot{tmp_dir.path()};             // contains bodies for [1'500'012, 1'500'013]
    test::SampleBodySnapshotPath body_snapshot_path{valid_body_snapshot.path()};  // necessary to tweak the block numbers
    auto body_index = BodyIndex::make(body_snapshot_path);
    REQUIRE_NOTHROW(body_index.build());

    Snapshot body_snapshot{body_snapshot_path};
    body_snapshot.reopen_segment();

    Index idx_body_number{body_snapshot_path.index_file()};
    idx_body_number.reopen_index();
    BodyFindByBlockNumQuery body_by_number{{body_snapshot, idx_body_number}};

    CHECK(!body_by_number.exec(1'500'011));
    CHECK(body_by_number.exec(1'500'012));
    const auto body_for_storage = body_by_number.exec(1'500'013);
    CHECK(body_for_storage.has_value());
    if (body_for_storage) {
        CHECK(body_for_storage->base_txn_id == 7'341'271);
        CHECK(body_for_storage->txn_count == 2 + 1);  // 2 system txs + 1 tx
    }
    // CHECK(!body_snapshot.body_by_number(1'500'014)); // TODO(canepat) assert in EF, should return std::nullopt instead
}

// https://etherscan.io/block/1500013
TEST_CASE("TransactionSnapshot::txn_by_id OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_snapshot{tmp_dir.path()};
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{tmp_dir.path()};           // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    auto tx_index = TransactionIndex::make(body_snapshot_path, tx_snapshot_path);
    CHECK_NOTHROW(tx_index.build());

    Snapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();

    Index idx_txn_hash{tx_snapshot_path.index_file()};
    idx_txn_hash.reopen_index();
    TransactionFindByIdQuery txn_by_id{{tx_snapshot, idx_txn_hash}};

    const auto transaction = txn_by_id.exec(7'341'272);
    CHECK(transaction.has_value());
    if (transaction) {
        CHECK(transaction->type == TransactionType::kLegacy);
        CHECK(transaction->sender() == 0x68795c4aa09d6f4ed3e5deddf8c2ad3049a601da_address);
        CHECK(transaction->to == 0xe9ae6ec1117bbfeb89302ce7e632597bc595efae_address);
    }
}

// https://etherscan.io/block/1500012
TEST_CASE("TransactionSnapshot::block_num_by_txn_hash OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_snapshot{tmp_dir.path()};
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{tmp_dir.path()};           // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    auto tx_index = TransactionIndex::make(body_snapshot_path, tx_snapshot_path);
    REQUIRE_NOTHROW(tx_index.build());
    auto tx_index_hash_to_block = TransactionToBlockIndex::make(body_snapshot_path, tx_snapshot_path);
    REQUIRE_NOTHROW(tx_index_hash_to_block.build());

    Snapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();

    Index idx_txn_hash{tx_snapshot_path.index_file()};
    idx_txn_hash.reopen_index();
    TransactionFindByIdQuery txn_by_id{{tx_snapshot, idx_txn_hash}};

    Index idx_txn_hash_2_block{tx_snapshot_path.index_file_for_type(SnapshotType::transactions_to_block)};
    idx_txn_hash_2_block.reopen_index();
    TransactionBlockNumByTxnHashQuery block_num_by_txn_hash{idx_txn_hash_2_block, TransactionFindByHashQuery{{tx_snapshot, idx_txn_hash}}};

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    auto transaction = txn_by_id.exec(7'341'269);  // known txn id in block 1'500'012
    CHECK(transaction.has_value());
    auto block_number = block_num_by_txn_hash.exec(transaction->hash());

    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'012);

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    transaction = txn_by_id.exec(7'341'272);  // known txn id in block 1'500'013
    CHECK(transaction.has_value());
    block_number = block_num_by_txn_hash.exec(transaction->hash());
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'013);

    // transaction hash not present in snapshot (first txn hash in block 1'500'014)
    block_number = block_num_by_txn_hash.exec(0xfa496b4cd9748754a28c66690c283ec9429440eb8609998901216908ad1b48eb_bytes32);
    CHECK_FALSE(block_number.has_value());
}

// https://etherscan.io/block/1500012
TEST_CASE("TransactionSnapshot::txn_range OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_snapshot{tmp_dir.path()};
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{tmp_dir.path()};           // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    auto tx_index = TransactionIndex::make(body_snapshot_path, tx_snapshot_path);
    REQUIRE_NOTHROW(tx_index.build());

    Snapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();

    Index idx_txn_hash{tx_snapshot_path.index_file()};
    idx_txn_hash.reopen_index();
    TransactionRangeFromIdQuery query{{tx_snapshot, idx_txn_hash}};

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    CHECK(query.exec_into_vector(7'341'263, 0).empty());
    CHECK(query.exec_into_vector(7'341'263, 7).size() == 7);

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    CHECK(query.exec_into_vector(7'341'272, 0).empty());
    CHECK(query.exec_into_vector(7'341'272, 1).size() == 1);

    // invalid base_txn_id returns empty
    CHECK(query.exec_into_vector(0, 1).empty());
    CHECK(query.exec_into_vector(10'000'000, 1).empty());
    CHECK(query.exec_into_vector(7'341'261, 1).empty());  // before the first system tx
    CHECK(query.exec_into_vector(7'341'274, 1).empty());  // after the last system tx
}

TEST_CASE("TransactionSnapshot::txn_rlp_range OK", "[silkworm][node][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_snapshot{tmp_dir.path()};
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{tmp_dir.path()};           // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    auto tx_index = TransactionIndex::make(body_snapshot_path, tx_snapshot_path);
    REQUIRE_NOTHROW(tx_index.build());

    Snapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();

    Index idx_txn_hash{tx_snapshot_path.index_file()};
    idx_txn_hash.reopen_index();
    TransactionPayloadRlpRangeFromIdQuery query{{tx_snapshot, idx_txn_hash}};

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    CHECK(query.exec_into_vector(7'341'263, 0).empty());
    CHECK(query.exec_into_vector(7'341'263, 7).size() == 7);

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    CHECK(query.exec_into_vector(7'341'272, 0).empty());
    CHECK(query.exec_into_vector(7'341'272, 1).size() == 1);

    // invalid base_txn_id returns empty
    CHECK(query.exec_into_vector(0, 1).empty());
    CHECK(query.exec_into_vector(10'000'000, 1).empty());
    CHECK(query.exec_into_vector(7'341'261, 1).empty());  // before the first system tx
    CHECK(query.exec_into_vector(7'341'274, 1).empty());  // after the last system tx
}

TEST_CASE("slice_tx_payload", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    const std::vector<AccessListEntry> access_list{
        {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
         {
             0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
             0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
         }},
        {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
    };

    SECTION("TransactionType: kLegacy") {
        Transaction txn{};
        txn.type = TransactionType::kLegacy;
        txn.chain_id = 1;
        txn.nonce = 12;
        txn.max_priority_fee_per_gas = 20000000000;
        txn.max_fee_per_gas = 20000000000;
        txn.gas_limit = 21000;
        txn.to = 0x727fc6a68321b754475c668a6abfb6e9e71c169a_address;
        txn.value = 10 * kEther;
        txn.data = *from_hex(
            "a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
            "00015af1d78b58c4000");
        txn.odd_y_parity = true;
        txn.r = intx::from_string<intx::uint256>("0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717");
        txn.s = intx::from_string<intx::uint256>("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718");
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = slice_tx_payload(encoded));
        CHECK(decoded == encoded);  // no envelope for legacy tx
    }
    SECTION("TransactionType: kAccessList") {
        Transaction txn{};
        txn.type = TransactionType::kAccessList;
        txn.chain_id = kSepoliaConfig.chain_id;
        txn.nonce = 7;
        txn.max_priority_fee_per_gas = 30000000000;
        txn.max_fee_per_gas = 30000000000;
        txn.gas_limit = 5748100;
        txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
        txn.value = 2 * kEther;
        txn.data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd");
        txn.access_list = access_list;
        txn.odd_y_parity = false;
        txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
        txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(2));  // 2-byte envelope for this access-list tx
    }
    SECTION("TransactionType: kDynamicFee") {
        Transaction txn{};
        txn.type = TransactionType::kDynamicFee;
        txn.chain_id = kSepoliaConfig.chain_id;
        txn.nonce = 7;
        txn.max_priority_fee_per_gas = 10000000000;
        txn.max_fee_per_gas = 30000000000;
        txn.gas_limit = 5748100;
        txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
        txn.value = 2 * kEther;
        txn.data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd");
        txn.access_list = access_list;
        txn.odd_y_parity = false;
        txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
        txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(2));  // 2-byte envelope for this dynamic-fee tx
    }
    SECTION("TransactionType: kBlob") {
        Transaction txn{};
        txn.type = TransactionType::kBlob;
        txn.chain_id = kSepoliaConfig.chain_id;
        txn.nonce = 7;
        txn.max_priority_fee_per_gas = 10000000000;
        txn.max_fee_per_gas = 30000000000;
        txn.gas_limit = 5748100;
        txn.to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address;
        txn.data = *from_hex("04f7");
        txn.access_list = access_list;
        txn.max_fee_per_blob_gas = 123;
        txn.blob_versioned_hashes = {
            0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
            0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
        };
        txn.odd_y_parity = true;
        txn.r = intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0");
        txn.s = intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094");
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(3));  // 3-byte envelope for this blob tx
    }
}

}  // namespace silkworm::snapshots
