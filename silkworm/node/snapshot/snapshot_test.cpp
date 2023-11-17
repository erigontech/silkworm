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

#include "snapshot.hpp"

#include <utility>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/snapshot/index.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshot {

using namespace std::chrono_literals;

static const SnapshotPath kValidHeadersSegmentPath{*SnapshotPath::parse("v1-014500-015000-headers.seg")};

class SnapshotPath_ForTest : public SnapshotPath {
  public:
    SnapshotPath_ForTest(BlockNum block_from, BlockNum block_to)
        : SnapshotPath(SnapshotPath::from(TemporaryDirectory::get_os_temporary_path(),
                                          kSnapshotV1,
                                          block_from,
                                          block_to,
                                          SnapshotType::headers)) {}
};

class Snapshot_ForTest : public Snapshot {
  public:
    explicit Snapshot_ForTest(SnapshotPath path) : Snapshot(path) {}
    explicit Snapshot_ForTest(std::filesystem::path path) : Snapshot(*SnapshotPath::parse(path)) {}
    Snapshot_ForTest(BlockNum block_from, BlockNum block_to) : Snapshot(SnapshotPath_ForTest{block_from, block_to}) {}
    ~Snapshot_ForTest() override { close(); }

    void reopen_index() override {}
    void close_index() override {}
};

class TransactionSnapshot_ForTest : public TransactionSnapshot {
  public:
    using TransactionSnapshot::decode_txn;
    using TransactionSnapshot::slice_tx_data;
    using TransactionSnapshot::slice_tx_payload;
};

template <class Rep, class Period>
static auto move_last_write_time(const std::filesystem::path& p, const std::chrono::duration<Rep, Period>& d) {
    const auto ftime = std::filesystem::last_write_time(p);
    std::filesystem::last_write_time(p, ftime + d);
    return std::filesystem::last_write_time(p) - ftime;
}

TEST_CASE("Snapshot::Snapshot", "[silkworm][node][snapshot][snapshot]") {
    SECTION("valid") {
        std::vector<std::pair<BlockNum, BlockNum>> block_ranges{
            {0, 1},
            {1'000, 1'000},
            {1'000, 2'000}};
        for (const auto& [block_from, block_to] : block_ranges) {
            Snapshot_ForTest snapshot{block_from, block_to};
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
            CHECK_THROWS_AS(Snapshot_ForTest(block_from, block_to), std::logic_error);
        }
    }
}

TEST_CASE("Snapshot::reopen_segment", "[silkworm][node][snapshot][snapshot]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{kValidHeadersSegmentPath.filename(), test::SnapshotHeader{}};
    Snapshot_ForTest snapshot{tmp_snapshot_file.path()};
    snapshot.reopen_segment();
}

TEST_CASE("Snapshot::for_each_item", "[silkworm][node][snapshot][snapshot]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::HelloWorldSnapshotFile hello_world_snapshot_file{kValidHeadersSegmentPath.filename()};
    huffman::Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path()};
    tmp_snapshot.reopen_segment();
    CHECK(!tmp_snapshot.empty());
    CHECK(tmp_snapshot.item_count() == 1);
    tmp_snapshot.for_each_item([&](const auto& word_item) {
        CHECK(std::string{word_item.value.cbegin(), word_item.value.cend()} == "hello, world");
        CHECK(word_item.position == 0);
        CHECK(word_item.offset == 0);
        return true;
    });
}

TEST_CASE("Snapshot::close", "[silkworm][node][snapshot][snapshot]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::HelloWorldSnapshotFile hello_world_snapshot_file{kValidHeadersSegmentPath.filename()};
    huffman::Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path()};
    tmp_snapshot.reopen_segment();
    CHECK_NOTHROW(tmp_snapshot.close());
}

// https://etherscan.io/block/1500013
TEST_CASE("HeaderSnapshot::header_by_number OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleHeaderSnapshotFile valid_header_snapshot{};                             // contains headers for [1'500'012, 1'500'013]
    test::SampleHeaderSnapshotPath header_snapshot_path{valid_header_snapshot.path()};  // necessary to tweak the block numbers
    HeaderIndex header_index{header_snapshot_path};
    REQUIRE_NOTHROW(header_index.build());

    HeaderSnapshot header_snapshot{header_snapshot_path};
    header_snapshot.reopen_segment();
    header_snapshot.reopen_index();

    CHECK(!header_snapshot.header_by_number(1'500'011));
    CHECK(header_snapshot.header_by_number(1'500'012));
    const auto header = header_snapshot.header_by_number(1'500'013);
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
    CHECK(!header_snapshot.header_by_number(1'500'014));
}

// https://etherscan.io/block/1500013
TEST_CASE("BodySnapshot::body_by_number OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleBodySnapshotFile valid_body_snapshot{};                           // contains bodies for [1'500'012, 1'500'013]
    test::SampleBodySnapshotPath body_snapshot_path{valid_body_snapshot.path()};  // necessary to tweak the block numbers
    BodyIndex body_index{body_snapshot_path};
    REQUIRE_NOTHROW(body_index.build());

    BodySnapshot body_snapshot{body_snapshot_path};
    body_snapshot.reopen_segment();
    body_snapshot.reopen_index();

    CHECK(!body_snapshot.body_by_number(1'500'011));
    CHECK(body_snapshot.body_by_number(1'500'012));
    const auto body_for_storage = body_snapshot.body_by_number(1'500'013);
    CHECK(body_for_storage.has_value());
    if (body_for_storage) {
        CHECK(body_for_storage->base_txn_id == 7'341'271);
        CHECK(body_for_storage->txn_count == 2 + 1);  // 2 system txs + 1 tx
    }
    // CHECK(!body_snapshot.body_by_number(1'500'014)); // TODO(canepat) assert in EF, should return std::nullopt instead
}

// https://etherscan.io/block/1500013
TEST_CASE("TransactionSnapshot::txn_by_id OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{};                         // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());

    TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();
    const auto transaction = tx_snapshot.txn_by_id(7'341'272);
    CHECK(transaction.has_value());
    if (transaction) {
        CHECK(transaction->type == TransactionType::kLegacy);
        CHECK(transaction->from == 0x68795c4aa09d6f4ed3e5deddf8c2ad3049a601da_address);
        CHECK(transaction->to == 0xe9ae6ec1117bbfeb89302ce7e632597bc595efae_address);
    }
}

// https://etherscan.io/block/1500012
TEST_CASE("TransactionSnapshot::block_num_by_txn_hash OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{};                         // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());

    TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    auto transaction = tx_snapshot.txn_by_id(7'341'269);  // known txn id in block 1'500'012
    CHECK(transaction.has_value());
    auto block_number = tx_snapshot.block_num_by_txn_hash(transaction->hash());

    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'012);

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    transaction = tx_snapshot.txn_by_id(7'341'272);  // known txn id in block 1'500'013
    CHECK(transaction.has_value());
    block_number = tx_snapshot.block_num_by_txn_hash(transaction->hash());
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'013);

    // transaction hash not present in snapshot (first txn hash in block 1'500'014)
    block_number = tx_snapshot.block_num_by_txn_hash(0xfa496b4cd9748754a28c66690c283ec9429440eb8609998901216908ad1b48eb_bytes32);
    CHECK(not block_number.has_value());
}

// https://etherscan.io/block/1500012
TEST_CASE("TransactionSnapshot::txn_range OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{};                         // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());

    TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    SECTION("1'500'012 OK") {
        CHECK(tx_snapshot.txn_range(7'341'263, 0, /*read_senders=*/true).empty());
        CHECK(tx_snapshot.txn_range(7'341'263, 7, /*read_senders=*/true).size() == 7);
    }
    SECTION("1'500'012 KO") {
        CHECK_THROWS(tx_snapshot.txn_range(7'341'262, 7, /*read_senders=*/true));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_range(7'341'264, 7, /*read_senders=*/true));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_range(7'341'263, 8, /*read_senders=*/true));  // invalid txn_count
    }

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    SECTION("1'500'013 OK") {
        CHECK(tx_snapshot.txn_range(7'341'272, 0, /*read_senders=*/true).empty());
        CHECK(tx_snapshot.txn_range(7'341'272, 1, /*read_senders=*/true).size() == 1);
    }
    SECTION("1'500'013 KO") {
        CHECK_THROWS(tx_snapshot.txn_range(7'341'271, 1, /*read_senders=*/true));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_range(7'341'273, 1, /*read_senders=*/true));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_range(7'341'272, 2, /*read_senders=*/true));  // invalid txn_count
    }
}

TEST_CASE("TransactionSnapshot::txn_rlp_range OK", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleTransactionSnapshotFile valid_tx_snapshot{};                         // contains txs for [1'500'012, 1'500'013]
    test::SampleTransactionSnapshotPath tx_snapshot_path{valid_tx_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());

    TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();

    // block 1'500'012: base_txn_id is 7'341'263, txn_count is 7
    SECTION("1'500'012 OK") {
        CHECK(tx_snapshot.txn_rlp_range(7'341'263, 0).empty());
        CHECK(tx_snapshot.txn_rlp_range(7'341'263, 7).size() == 7);
    }
    SECTION("1'500'012 KO") {
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'262, 7));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'264, 7));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'263, 8));  // invalid txn_count
    }

    // block 1'500'013: base_txn_id is 7'341'272, txn_count is 1
    SECTION("1'500'013 OK") {
        CHECK(tx_snapshot.txn_rlp_range(7'341'272, 0).empty());
        CHECK(tx_snapshot.txn_rlp_range(7'341'272, 1).size() == 1);
    }
    SECTION("1'500'013 KO") {
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'271, 1));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'273, 1));  // invalid base_txn_id
        CHECK_THROWS(tx_snapshot.txn_rlp_range(7'341'272, 2));  // invalid txn_count
    }
}

TEST_CASE("TransactionSnapshot::slice_tx_payload", "[silkworm][node][snapshot]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    const std::vector<AccessListEntry> access_list{
        {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
         {
             0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
             0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
         }},
        {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
    };

    SECTION("TransactionType: kLegacy") {
        Transaction txn{
            {.type = TransactionType::kLegacy,
             .chain_id = 1,
             .nonce = 12,
             .max_priority_fee_per_gas = 20000000000,
             .max_fee_per_gas = 20000000000,
             .gas_limit = 21000,
             .to = 0x727fc6a68321b754475c668a6abfb6e9e71c169a_address,
             .value = 10 * kEther,
             .data = *from_hex("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc9716000000000000000000"
                               "00015af1d78b58c4000")},
            true,                                                                                                    // odd_y_parity
            intx::from_string<intx::uint256>("0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717"),  // r
            intx::from_string<intx::uint256>("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718"),  // s
        };
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = TransactionSnapshot_ForTest::slice_tx_payload(encoded));
        CHECK(decoded == encoded);  // no envelope for legacy tx
    }
    SECTION("TransactionType: kAccessList") {
        Transaction txn{
            {.type = TransactionType::kAccessList,
             .chain_id = 5,
             .nonce = 7,
             .max_priority_fee_per_gas = 30000000000,
             .max_fee_per_gas = 30000000000,
             .gas_limit = 5748100,
             .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
             .value = 2 * kEther,
             .data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd"),
             .access_list = access_list},
            false,                                                                                                   // odd_y_parity
            intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
            intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
        };
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = TransactionSnapshot_ForTest::slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(2));  // 2-byte envelope for this access-list tx
    }
    SECTION("TransactionType: kDynamicFee") {
        Transaction txn{
            {.type = TransactionType::kDynamicFee,
             .chain_id = 5,
             .nonce = 7,
             .max_priority_fee_per_gas = 10000000000,
             .max_fee_per_gas = 30000000000,
             .gas_limit = 5748100,
             .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
             .value = 2 * kEther,
             .data = *from_hex("6ebaf477f83e051589c1188bcc6ddccd"),
             .access_list = access_list},
            false,                                                                                                   // odd_y_parity
            intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
            intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
        };
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = TransactionSnapshot_ForTest::slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(2));  // 2-byte envelope for this dynamic-fee tx
    }
    SECTION("TransactionType: kBlob") {
        Transaction txn{
            {.type = TransactionType::kBlob,
             .chain_id = 5,
             .nonce = 7,
             .max_priority_fee_per_gas = 10000000000,
             .max_fee_per_gas = 30000000000,
             .gas_limit = 5748100,
             .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
             .data = *from_hex("04f7"),
             .access_list = access_list,
             .max_fee_per_blob_gas = 123,
             .blob_versioned_hashes = {
                 0xc6bdd1de713471bd6cfa62dd8b5a5b42969ed09e26212d3377f3f8426d8ec210_bytes32,
                 0x8aaeccaf3873d07cef005aca28c39f8a9f8bdb1ec8d79ffc25afc0a4fa2ab736_bytes32,
             }},
            true,                                                                                                    // odd_y_parity
            intx::from_string<intx::uint256>("0x36b241b061a36a32ab7fe86c7aa9eb592dd59018cd0443adc0903590c16b02b0"),  // r
            intx::from_string<intx::uint256>("0x5edcc541b4741c5cc6dd347c5ed9577ef293a62787b4510465fadbfe39ee4094"),  // s
        };
        Bytes encoded{};
        rlp::encode(encoded, txn);
        Bytes decoded{};
        CHECK_NOTHROW(decoded = TransactionSnapshot_ForTest::slice_tx_payload(encoded));
        CHECK(decoded == encoded.substr(3));  // 3-byte envelope for this blob tx
    }
}

TEST_CASE("HeaderSnapshot::reopen_index regeneration", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleHeaderSnapshotFile sample_header_snapshot{};
    test::SampleHeaderSnapshotPath header_snapshot_path{sample_header_snapshot.path()};
    HeaderIndex header_index{header_snapshot_path};
    REQUIRE_NOTHROW(header_index.build());

    HeaderSnapshot header_snapshot{header_snapshot_path};
    header_snapshot.reopen_segment();
    header_snapshot.reopen_index();
    REQUIRE(std::filesystem::exists(header_snapshot.path().index_file().path()));

    // Move 1 hour to the future the last write time for sample header snapshot
    const auto last_write_time_diff = move_last_write_time(sample_header_snapshot.path(), 1h);
    REQUIRE(last_write_time_diff > std::filesystem::file_time_type::duration::zero());

    // Verify that reopening the index removes the index file because it was created in the past
    CHECK(std::filesystem::exists(header_snapshot.path().index_file().path()));
    header_snapshot.reopen_index();
    CHECK(not std::filesystem::exists(header_snapshot.path().index_file().path()));
}

TEST_CASE("BodySnapshot::reopen_index regeneration", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleBodySnapshotFile sample_body_snapshot{};
    test::SampleBodySnapshotPath body_snapshot_path{sample_body_snapshot.path()};
    BodyIndex body_index{body_snapshot_path};
    REQUIRE_NOTHROW(body_index.build());

    BodySnapshot body_snapshot{body_snapshot_path};
    body_snapshot.reopen_segment();
    body_snapshot.reopen_index();
    CHECK(std::filesystem::exists(body_snapshot.path().index_file().path()));

    // Move 1 hour to the future the last write time for sample body snapshot
    const auto last_write_time_diff = move_last_write_time(sample_body_snapshot.path(), 1h);
    REQUIRE(last_write_time_diff > std::filesystem::file_time_type::duration::zero());

    // Verify that reopening the index removes the index file if created in the past
    CHECK(std::filesystem::exists(body_snapshot.path().index_file().path()));
    body_snapshot.reopen_index();
    CHECK(not std::filesystem::exists(body_snapshot.path().index_file().path()));
}

TEST_CASE("TransactionSnapshot::reopen_index regeneration", "[silkworm][node][snapshot][index]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleTransactionSnapshotFile sample_tx_snapshot{};
    test::SampleTransactionSnapshotPath tx_snapshot_path{sample_tx_snapshot.path()};
    TransactionIndex tx_index{tx_snapshot_path};
    REQUIRE_NOTHROW(tx_index.build());

    TransactionSnapshot tx_snapshot{tx_snapshot_path};
    tx_snapshot.reopen_segment();
    tx_snapshot.reopen_index();
    CHECK(std::filesystem::exists(tx_snapshot.path().index_file().path()));

    // Move 1 hour to the future the last write time for sample tx snapshot
    const auto last_write_time_diff = move_last_write_time(sample_tx_snapshot.path(), 1h);
    REQUIRE(last_write_time_diff > std::filesystem::file_time_type::duration::zero());

    // Verify that reopening the index removes the index file if created in the past
    CHECK(std::filesystem::exists(tx_snapshot.path().index_file().path()));
    tx_snapshot.reopen_index();
    CHECK(not std::filesystem::exists(tx_snapshot.path().index_file().path()));
}

}  // namespace silkworm::snapshot
