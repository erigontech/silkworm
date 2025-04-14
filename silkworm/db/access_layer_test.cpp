// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "access_layer.hpp"

#include <stdexcept>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/db/datastore/kvdb/bitmap.hpp>
#include <silkworm/db/prune_mode.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/db/state/account_codec.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>

#include "test_util/mock_ro_cursor.hpp"
#include "test_util/mock_txn.hpp"

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

    body.transactions[1].type = TransactionType::kDynamicFee;
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
    body.ommers[0].prev_randao = 0xf0a53dfdd6c2f2a661e718ef29092de60d81d45f84044bec7bf4b36630b2bc08_bytes32;
    body.ommers[0].nonce[7] = 35;

    return body;
}

// https://etherscan.io/block/17035047
static BlockBody block_body_17035047() {
    constexpr evmc::address kRecipient1{0x40458B394D1C2A9aA095dd169a6EB43a73949fa3_address};
    constexpr evmc::address kRecipient2{0xEdA2B3743d37a2a5bD4EB018d515DC47B7802EB4_address};
    BlockBody body;
    body.withdrawals = std::vector<Withdrawal>{};
    body.withdrawals->reserve(16);
    body.withdrawals->emplace_back(Withdrawal{2733, 157233, kRecipient1, 3148401251});
    body.withdrawals->emplace_back(Withdrawal{2734, 157234, kRecipient1, 2797715671});
    body.withdrawals->emplace_back(Withdrawal{2735, 157235, kRecipient1, 2987093215});
    body.withdrawals->emplace_back(Withdrawal{2736, 157236, kRecipient1, 2917273462});
    body.withdrawals->emplace_back(Withdrawal{2737, 157237, kRecipient1, 2873029573});
    body.withdrawals->emplace_back(Withdrawal{2738, 157238, kRecipient1, 0316444461});
    body.withdrawals->emplace_back(Withdrawal{2739, 157239, kRecipient1, 3076965697});
    body.withdrawals->emplace_back(Withdrawal{2740, 157240, kRecipient1, 3264826534});
    body.withdrawals->emplace_back(Withdrawal{2741, 157241, kRecipient1, 2959830042});
    body.withdrawals->emplace_back(Withdrawal{2742, 157242, kRecipient1, 2858527882});
    body.withdrawals->emplace_back(Withdrawal{2743, 157243, kRecipient1, 2972530438});
    body.withdrawals->emplace_back(Withdrawal{2744, 157244, kRecipient1, 2897978772});
    body.withdrawals->emplace_back(Withdrawal{2745, 157245, kRecipient1, 2946132889});
    body.withdrawals->emplace_back(Withdrawal{2746, 157246, kRecipient1, 2918951932});
    body.withdrawals->emplace_back(Withdrawal{2747, 157247, kRecipient1, 2902163625});
    body.withdrawals->emplace_back(Withdrawal{2748, 157248, kRecipient2, 2846508033});
    return body;
}

}  // namespace silkworm

namespace silkworm::db {

using namespace silkworm::datastore::kvdb;
using datastore::kvdb::to_slice;

TEST_CASE("Methods cursor_for_each/cursor_for_count", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    ::mdbx::map_handle main_map{1};
    auto main_stat{txn->get_map_stat(main_map)};
    PooledCursor main_crs{txn, main_map};
    std::vector<std::string> table_names{};

    const auto walk_func{[&table_names](ByteView key, ByteView) {
        table_names.emplace_back(byte_ptr_cast(key.data()));
    }};

    main_crs.to_first();
    cursor_for_each(main_crs, walk_func);
    CHECK(table_names.size() == sizeof(table::kChainDataTables) / sizeof(table::kChainDataTables[0]));
    CHECK(table_names.size() == main_stat.ms_entries);

    main_crs.to_first();
    size_t max_count = table_names.size() - 1;
    table_names.clear();
    cursor_for_count(main_crs, walk_func, max_count);
    CHECK(table_names.size() == max_count);
}

TEST_CASE("VersionBase primitives", "[db][access_layer]") {
    VersionBase v1{0, 0, 0};
    VersionBase v2{0, 0, 1};
    VersionBase v3{0, 0, 1};
    CHECK(v1 != v2);
    CHECK(v2 > v1);
    CHECK(v2 >= v1);
    CHECK(v1 <= v2);
    CHECK(v2 == v3);
}

TEST_CASE("Sequences", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    auto val1{read_map_sequence(txn, table::kBlockTransactions.name)};
    CHECK(val1 == 0);

    auto val2{increment_map_sequence(txn, table::kBlockTransactions.name, 5)};
    CHECK(val2 == 0);
    auto val3{read_map_sequence(txn, table::kBlockTransactions.name)};
    CHECK(val3 == 5);

    auto val4{increment_map_sequence(txn, table::kBlockTransactions.name, 3)};
    CHECK(val4 == 5);
    auto val5{read_map_sequence(txn, table::kBlockTransactions.name)};
    CHECK(val5 == 8);

    context.commit_and_renew_txn();
    auto& txn2{context.rw_txn()};

    auto val6{read_map_sequence(txn2, table::kBlockTransactions.name)};
    CHECK(val6 == 8);

    // Reset sequence
    auto val7{reset_map_sequence(txn2, table::kBlockTransactions.name, 19)};
    CHECK(val7 == 8);

    auto val8{read_map_sequence(txn2, table::kBlockTransactions.name)};
    CHECK(val8 == 19);

    // Tamper with sequence
    Bytes fake_value(sizeof(uint32_t), '\0');
    mdbx::slice key(table::kBlockTransactions.name);
    auto tgt{open_cursor(txn2, table::kSequence)};
    tgt.upsert(key, to_slice(fake_value));

    bool thrown{false};
    try {
        (void)increment_map_sequence(txn, table::kBlockTransactions.name);
    } catch (const std::exception& ex) {
        REQUIRE(std::string(ex.what()) == "Bad sequence value in db");
        thrown = true;
    }
    CHECK(thrown);
}

TEST_CASE("Schema Version", "[db][access_layer]") {
    test_util::TempChainData context(/*with_create_tables=*/false);

    SECTION("Read/Write") {
        auto version{read_schema_version(context.rw_txn())};
        CHECK(version.has_value() == false);

        version = VersionBase{3, 0, 0};
        CHECK_NOTHROW(write_schema_version(context.rw_txn(), version.value()));
        context.commit_and_renew_txn();
        version = read_schema_version(context.rw_txn());
        CHECK(version.has_value() == true);

        auto version2{read_schema_version(context.rw_txn())};
        CHECK(version.value() == version2.value());

        version2 = VersionBase{2, 0, 0};
        CHECK_THROWS(write_schema_version(context.rw_txn(), version2.value()));

        version2 = VersionBase{3, 1, 0};
        CHECK_NOTHROW(write_schema_version(context.rw_txn(), version2.value()));
    }

    SECTION("Incompatible schema") {
        // Reduce compat schema version
        constexpr VersionBase kIncompatibleVersion{table::kRequiredSchemaVersion.major - 1, 0, 0};
        REQUIRE_NOTHROW(write_schema_version(context.rw_txn(), kIncompatibleVersion));
        REQUIRE_THROWS(table::check_or_create_chaindata_tables(context.rw_txn()));
    }

    SECTION("Incompatible table") {
        (void)context.txn().create_map(table::kBlockBodies.name_str(), mdbx::key_mode::reverse,
                                       mdbx::value_mode::multi_reverse);
        REQUIRE_THROWS(table::check_or_create_chaindata_tables(context.rw_txn()));
    }
}

TEST_CASE("Storage and Prune Modes", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.txn()};

    SECTION("Prune Mode") {
        BlockAmount block_amount;
        REQUIRE(block_amount.value() == 0);
        REQUIRE(block_amount.value_from_head(1'000'000) == 0);

        // Uninitialized mode
        PruneMode default_mode{};
        CHECK(default_mode.to_string() == "--prune=");

        // No value in db -> no pruning
        {
            auto prune_mode{read_prune_mode(txn)};
            CHECK(prune_mode.to_string() == "--prune=");
            CHECK_NOTHROW(write_prune_mode(txn, prune_mode));
            auto db_prune_mode = std::make_unique<PruneMode>(read_prune_mode(txn));
            REQUIRE(prune_mode == *db_prune_mode);
        }

        // Cross-check we have the same value
        {
            auto prune_mode = read_prune_mode(txn);
            CHECK(prune_mode.to_string() == "--prune=");
        }

        // Write rubbish to prune mode
        {
            auto target{open_cursor(txn, table::kDatabaseInfo)};
            std::string db_key{"pruneHistoryType"};
            std::string db_value{"random"};
            target.upsert(mdbx::slice(db_key), mdbx::slice(db_value));
            bool has_thrown{false};
            try {
                (void)read_prune_mode(txn);
            } catch (const std::runtime_error&) {
                has_thrown = true;
            }
            REQUIRE(has_thrown);
            db_value = "older";
            target.upsert(mdbx::slice(db_key), mdbx::slice(db_value));
        }

        // Provide different combinations of cli arguments
        std::string prune, expected;
        PruneDistance older_history, older_receipts, older_senders, older_tx_index, older_call_traces;
        PruneThreshold before_history, before_receipts, before_senders, before_tx_index, before_call_traces;

        prune = "hrstc";
        expected = "--prune=hrstc";
        {
            auto prune_mode =
                parse_prune_mode(prune,  //
                                 older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                                 before_history, before_receipts, before_senders, before_tx_index, before_call_traces);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE_NOTHROW(write_prune_mode(txn, prune_mode));
            prune_mode = read_prune_mode(txn);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE(prune_mode.history().value_from_head(10) == 0);
        }

        prune = "htc";
        older_history.emplace(8000);
        older_senders.emplace(80000);
        before_receipts.emplace(10000);
        expected = "--prune=tc --prune.h.older=8000 --prune.r.before=10000 --prune.s.older=80000";
        {
            auto prune_mode =
                parse_prune_mode(prune,  //
                                 older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                                 before_history, before_receipts, before_senders, before_tx_index, before_call_traces);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE_NOTHROW(write_prune_mode(txn, prune_mode));
            prune_mode = read_prune_mode(txn);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE(prune_mode.history() != prune_mode.receipts());
            REQUIRE(prune_mode.tx_index() == prune_mode.call_traces());
        }

        prune = "htc";
        older_history.emplace(kFullImmutabilityThreshold);
        older_senders.reset();
        before_receipts.emplace(10000);
        expected = "--prune=htc --prune.r.before=10000";
        {
            auto prune_mode =
                parse_prune_mode(prune,  //
                                 older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                                 before_history, before_receipts, before_senders, before_tx_index, before_call_traces);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE_NOTHROW(write_prune_mode(txn, prune_mode));
            prune_mode = read_prune_mode(txn);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE(prune_mode.receipts().value() == 10000);
            REQUIRE(prune_mode.history().value() == kFullImmutabilityThreshold);
        }

        prune = "hrtc";
        older_history.emplace(kFullImmutabilityThreshold + 5);
        before_receipts.reset();
        before_call_traces.emplace(10000);
        expected = "--prune=rt --prune.h.older=90005 --prune.c.before=10000";
        {
            auto prune_mode =
                parse_prune_mode(prune,  //
                                 older_history, older_receipts, older_senders, older_tx_index, older_call_traces,
                                 before_history, before_receipts, before_senders, before_tx_index, before_call_traces);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE_NOTHROW(write_prune_mode(txn, prune_mode));
            prune_mode = read_prune_mode(txn);
            REQUIRE(prune_mode.to_string() == expected);
            REQUIRE(prune_mode.receipts().value() == kFullImmutabilityThreshold);
            REQUIRE(prune_mode.tx_index().value() == kFullImmutabilityThreshold);
            REQUIRE(prune_mode.call_traces().type() == BlockAmount::Type::kBefore);
            REQUIRE(prune_mode.history().value_from_head(1'000'000) == 909'995);
            REQUIRE(prune_mode.receipts().value_from_head(1'000'000) == 910'000);
            REQUIRE(prune_mode.tx_index().value_from_head(1'000'000) == 910'000);
            REQUIRE(prune_mode.call_traces().type() == BlockAmount::Type::kBefore);
            REQUIRE(prune_mode.call_traces().value_from_head(1'000'000) == 9'999);
        }
    }
}

TEST_CASE("Stages", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    // Querying a non-existent stage name should throw
    CHECK_THROWS(stages::read_stage_progress(txn, "NonExistentStage"));

    // Not valued stage should return 0
    CHECK(stages::read_stage_progress(txn, stages::kBlockBodiesKey) == 0);

    // Value a stage progress and check returned value
    uint64_t block_num{0};
    uint64_t expected_block_num{123456};
    CHECK_NOTHROW(stages::write_stage_progress(txn, stages::kBlockBodiesKey, expected_block_num));
    CHECK_NOTHROW(block_num = stages::read_stage_progress(txn, stages::kBlockBodiesKey));
    CHECK(block_num == expected_block_num);

    // Write voluntary wrong value in stage
    Bytes stage_progress(2, 0);
    auto map{open_cursor(txn, table::kSyncStageProgress)};
    CHECK_NOTHROW(txn->upsert(map, mdbx::slice{stages::kBlockBodiesKey}, to_slice(stage_progress)));
    CHECK_THROWS(block_num = stages::read_stage_progress(txn, stages::kBlockBodiesKey));

    // Check "prune_" prefix
    CHECK_NOTHROW(stages::write_stage_prune_progress(txn, stages::kBlockBodiesKey, expected_block_num));
    CHECK_NOTHROW(block_num = stages::read_stage_prune_progress(txn, stages::kBlockBodiesKey));
    CHECK(block_num == expected_block_num);
    CHECK_NOTHROW(stages::write_stage_prune_progress(txn, stages::kBlockBodiesKey, 0));
    CHECK(stages::read_stage_prune_progress(txn, stages::kBlockBodiesKey) == 0);
}

TEST_CASE("Difficulty", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    BlockNum block_num{10};
    uint8_t hash[kHashLength]{};
    intx::uint256 difficulty{10};

    write_total_difficulty(txn, block_num, hash, difficulty);
    CHECK(read_total_difficulty(txn, block_num, hash) == difficulty);
}

TEST_CASE("Headers and bodies", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

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

    // Read back canonical header hash
    auto db_hash{read_canonical_header_hash(txn, block_num)};
    REQUIRE(db_hash.has_value());
    REQUIRE(memcmp(hash.bytes, db_hash.value().bytes, sizeof(hash)) == 0);

    // Read canonical head
    auto [head_block_num, head_hash] = read_canonical_head(txn);
    REQUIRE(head_block_num == header.number);
    REQUIRE(head_hash == header.hash());

    // Read non-existent canonical header hash
    db_hash = read_canonical_header_hash(txn, block_num + 1);
    REQUIRE(db_hash.has_value() == false);

    std::optional<BlockHeader> header_from_db{read_header(txn, header.number, hash.bytes)};
    REQUIRE(header_from_db.has_value());
    CHECK(*header_from_db == header);

    SECTION("read_block_by_number") {
        Block block;

        bool read_senders{false};
        CHECK(!read_block_by_number(txn, block_num, read_senders, block));

        BlockBody body{sample_block_body()};
        CHECK_NOTHROW(write_body(txn, body, hash.bytes, header.number));

        REQUIRE(read_block_by_number(txn, block_num, read_senders, block));
        CHECK(block.header == header);
        CHECK(block.ommers == body.ommers);
        CHECK(block.transactions == body.transactions);

        read_senders = true;
        CHECK_NOTHROW(read_block_by_number(txn, block_num, read_senders, block));

        Bytes full_senders{
            *from_hex("5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c"
                      "941591b6ca8e8dd05c69efdec02b77c72dac1496")};
        REQUIRE(full_senders.size() == 2 * kAddressLength);

        Bytes key{block_key(header.number, hash.bytes)};
        auto sender_table{open_cursor(txn, table::kSenders)};
        sender_table.upsert(to_slice(key), to_slice(full_senders));
        REQUIRE(read_block_by_number(txn, block_num, read_senders, block));
        CHECK(block.header == header);
        CHECK(block.ommers == body.ommers);
        CHECK(block.transactions == body.transactions);

        CHECK(block.transactions[0].sender() == 0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c_address);
        CHECK(block.transactions[1].sender() == 0x941591b6ca8e8dd05c69efdec02b77c72dac1496_address);

        auto [b, h] = split_block_key(key);
        REQUIRE(b == header.number);
        REQUIRE(h == header.hash());
    }

    SECTION("read_blocks") {
        BlockBody body{sample_block_body()};
        CHECK_NOTHROW(write_body(txn, body, header.hash(), header.number));

        size_t count = 0;
        auto processed = read_blocks(
            txn,
            block_num,
            [&count, &block_num](const Block& block) {
                REQUIRE(block.header.number == block_num);
                ++count;
            });
        REQUIRE(processed == 1);
        REQUIRE(processed == count);

        BlockBody body2{sample_block_body()};
        header.extra_data = string_view_to_byte_view("I'm different");
        CHECK_NOTHROW(write_header(txn, header, /*with_header_numbers=*/true));
        CHECK_NOTHROW(write_body(txn, body, header.hash(), header.number));  // another body at same block_num
        BlockBody body3{sample_block_body()};
        header.number = header.number + 1;
        CHECK_NOTHROW(write_header(txn, header, /*with_header_numbers=*/true));
        CHECK_NOTHROW(write_body(txn, body, hash.bytes, header.number));  // another body after the prev two

        count = 0;
        processed = read_blocks(
            txn,
            block_num,
            [&count, &block_num](const Block& block) {
                REQUIRE(block.header.number == block_num);
                ++count;
            });
        REQUIRE(processed == 2);
        REQUIRE(processed == count);
    }
}

TEST_CASE("Storage", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    PooledCursor table{txn, table::kPlainState};

    const evmc::address addr{0xb000000000000000000000000000000000000008_address};
    const Bytes key{storage_prefix(addr, kDefaultIncarnation)};

    const evmc::bytes32 loc1{0x000000000000000000000000000000000000a000000000000000000000000037_bytes32};
    const evmc::bytes32 loc2{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};
    const evmc::bytes32 loc3{0xff00000000000000000000000000000000000000000000000000000000000017_bytes32};
    const evmc::bytes32 loc4{0x00000000000000000000000000000000000000000000000000000000000f3128_bytes32};

    const evmc::bytes32 val1{0x00000000000000000000000000000000000000000000000000000000c9b131a4_bytes32};
    const evmc::bytes32 val2{0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
    const evmc::bytes32 val3{0x4400000000000000000000000000000000000000000000000000000000000000_bytes32};

    upsert_storage_value(table, key, loc1.bytes, val1.bytes);
    upsert_storage_value(table, key, loc2.bytes, val2.bytes);
    upsert_storage_value(table, key, loc3.bytes, val3.bytes);

    CHECK(read_storage(txn, addr, kDefaultIncarnation, loc1) == val1);
    CHECK(read_storage(txn, addr, kDefaultIncarnation, loc2) == val2);
    CHECK(read_storage(txn, addr, kDefaultIncarnation, loc3) == val3);
    CHECK(read_storage(txn, addr, kDefaultIncarnation, loc4) == evmc::bytes32{});
}

TEST_CASE("Account history", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    BlockNum block_num{42};

    AccountChanges changes{read_account_changes(txn, block_num)};
    CHECK(changes.empty());

    const evmc::address account_address{0x63c696931d3d3fd7cd83472febd193488266660d_address};
    const Account account{
        .nonce = 21,
        .balance = 1 * kEther,
        .code_hash = kEmptyHash,
        .incarnation = 3,
    };

    auto ah_cursor{txn.rw_cursor_dup_sort(table::kAccountHistory)};
    auto acs_cursor{txn.rw_cursor_dup_sort(table::kAccountChangeSet)};

    // Account change set for block_num
    Bytes acs_key{block_key(block_num)};
    Bytes acs_data{ByteView{account_address}};
    acs_data.append(state::AccountCodec::encode_for_storage(account));
    acs_cursor->upsert(to_slice(acs_key), to_slice(acs_data));

    Bytes ah_key{account_history_key(account_address, UINT64_MAX)};
    roaring::Roaring64Map bitmap({block_num});
    ah_cursor->upsert(to_slice(ah_key), to_slice(bitmap::to_bytes(bitmap)));

    std::optional<uint64_t> previous_incarnation{read_previous_incarnation(txn, account_address, block_num - 1)};
    REQUIRE(previous_incarnation.has_value());
    CHECK(*previous_incarnation == account.incarnation - 1);
}

TEST_CASE("Account changes", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

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

    auto table{open_cursor(txn, table::kAccountChangeSet)};

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

TEST_CASE("Storage changes", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

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

    auto table{open_cursor(txn, table::kStorageChangeSet)};

    Bytes data1{ByteView{location1}};
    data1.append(val1);
    auto key1{storage_change_key(block_num1, addr1, incarnation1)};
    table.upsert(to_slice(key1), to_slice(data1));

    Bytes data2{ByteView{location2}};
    data2.append(val2);
    auto key2{storage_change_key(block_num1, addr2, incarnation2)};
    table.upsert(to_slice(key2), to_slice(data2));

    Bytes data3{ByteView{location3}};
    data3.append(val3);
    auto key3{storage_change_key(block_num1, addr3, incarnation3)};
    table.upsert(to_slice(key3), to_slice(data3));

    Bytes data4{ByteView{location4}};
    data4.append(val4);
    auto key4{storage_change_key(block_num3, addr4, incarnation4)};
    table.upsert(to_slice(key4), to_slice(data4));

    CHECK(txn->get_map_stat(table.map()).ms_entries == 4);

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

TEST_CASE("Chain config", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    const auto chain_config1{read_chain_config(txn)};
    CHECK(chain_config1 == std::nullopt);

    auto canonical_hashes{open_cursor(txn, table::kCanonicalHashes)};
    const Bytes genesis_block_key{block_key(0)};
    canonical_hashes.upsert(to_slice(genesis_block_key), to_slice(kSepoliaGenesisHash));

    const auto chain_config2{read_chain_config(txn)};
    CHECK(chain_config2 == std::nullopt);

    auto config_table{open_cursor(txn, table::kConfig)};
    const std::string sepolia_config_json{kSepoliaConfig.to_json().dump()};
    config_table.upsert(to_slice(kSepoliaGenesisHash), mdbx::slice{sepolia_config_json.c_str()});

    const auto chain_config3{read_chain_config(txn)};
    CHECK(chain_config3 == kSepoliaConfig);
}

TEST_CASE("Head header", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    REQUIRE(read_head_header_hash(txn) == std::nullopt);
    REQUIRE_NOTHROW(write_head_header_hash(txn, kSepoliaGenesisHash));
    REQUIRE(read_head_header_hash(txn).value() == kSepoliaGenesisHash);
}

TEST_CASE("Last Fork Choice", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    auto hash1 = 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32;
    auto hash2 = 0xc2bcdfd012534fa0b19ffba5fae6fc81edd390e9b7d5007d1e92e8e835286e9d_bytes32;
    auto hash3 = 0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804_bytes32;

    write_last_head_block(txn, hash1);
    write_last_safe_block(txn, hash2);
    write_last_finalized_block(txn, hash3);

    CHECK(read_last_head_block(txn) == hash1);
    CHECK(read_last_safe_block(txn) == hash2);
    CHECK(read_last_finalized_block(txn) == hash3);
}

TEST_CASE("read rlp encoded transactions", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    uint64_t block_num{11'054'435};

    BlockHeader header;
    header.number = block_num;
    header.beneficiary = 0x09ab1303d3ccaf5f018cd511146b07a240c70294_address;
    header.gas_limit = 12'451'080;
    header.gas_used = 12'443'619;

    auto hash = header.hash();

    BlockBody body{sample_block_body()};
    CHECK_NOTHROW(write_body(txn, body, hash.bytes, header.number));

    std::vector<Bytes> rlp_transactions;
    bool found = read_rlp_transactions(txn, header.number, hash, rlp_transactions);

    REQUIRE(found);
    REQUIRE(rlp_transactions.size() == body.transactions.size());

    for (size_t i = 0; i < rlp_transactions.size(); ++i) {
        Bytes rlp_tx;
        CHECK_NOTHROW(rlp::encode(rlp_tx, body.transactions[i]));
        CHECK(rlp_transactions[i] == rlp_tx);
    }
}

TEST_CASE("write and read body w/ withdrawals", "[db][access_layer]") {
    test_util::TempChainData context;
    auto& txn{context.rw_txn()};

    BlockHeader header;
    header.number = 17'035'047;
    header.beneficiary = 0xe688b84b23f322a994A53dbF8E15FA82CDB71127_address;
    header.gas_limit = 30'000'000;
    header.gas_used = 0;

    const auto hash = header.hash();

    BlockBody body_in{block_body_17035047()};
    CHECK_NOTHROW(write_body(txn, body_in, hash.bytes, header.number));
    BlockBody body_out{};
    CHECK_NOTHROW(read_body(txn, header.number, hash.bytes, false, body_out));
    CHECK(body_out == body_in);
}

using testing::_;
using testing::InvokeWithoutArgs;

static void expect_mock_ro_cursor(test_util::MockROTxn& mock_ro_txn, test_util::MockROCursor* mock_ro_cursor) {
    EXPECT_CALL(mock_ro_txn, ro_cursor(_))
        .WillOnce(InvokeWithoutArgs([=]() mutable -> std::unique_ptr<ROCursor> {
            return std::unique_ptr<test_util::MockROCursor>(mock_ro_cursor);
        }));
}

struct AccessLayerTest {
    explicit AccessLayerTest() {
        expect_mock_ro_cursor(mock_ro_txn, mock_ro_cursor);
    }

    test_util::MockROTxn mock_ro_txn;
    test_util::MockROCursor* mock_ro_cursor = new test_util::MockROCursor;
};

static constexpr Hash kBlockHash;  // empty but it doesn't matter for the tests
static constexpr ::mdbx::slice kValidBlockHashSlice{kBlockHash.bytes, kHashLength};
static constexpr ::mdbx::slice kInvalidBlockHashSlice{kBlockHash.bytes, 30};
static const Bytes kValidEncodedBlockNum{*from_hex("0000000000000002")};
static const Bytes kInvalidEncodedBlockNum{*from_hex("0002")};

TEST_CASE_METHOD(AccessLayerTest, "read_block_num", "[db][access_layer]") {
    const ::mdbx::slice valid_block_num_slice{kValidEncodedBlockNum};
    const ::mdbx::slice invalid_block_num_slice{kInvalidEncodedBlockNum};

    SECTION("valid block number") {
        EXPECT_CALL(*mock_ro_cursor, find(kValidBlockHashSlice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{kValidBlockHashSlice, valid_block_num_slice, /*.done=*/true};
            }));
        CHECK(read_block_num(mock_ro_txn, kBlockHash) == 2);
    }
    SECTION("data not found") {
        EXPECT_CALL(*mock_ro_cursor, find(kValidBlockHashSlice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{::mdbx::slice{}, ::mdbx::slice{}, /*.done=*/false};
            }));
        CHECK_FALSE(read_block_num(mock_ro_txn, kBlockHash));
    }
    SECTION("invalid block number value size") {
        EXPECT_CALL(*mock_ro_cursor, find(kValidBlockHashSlice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{kValidBlockHashSlice, invalid_block_num_slice, /*.done=*/true};
            }));
        CHECK_THROWS_AS(read_block_num(mock_ro_txn, kBlockHash), std::length_error);
    }
}

TEST_CASE_METHOD(AccessLayerTest, "read_canonical_head", "[db][access_layer]") {
    const ::mdbx::slice valid_block_num_slice{kValidEncodedBlockNum};
    const ::mdbx::slice invalid_block_num_slice{kInvalidEncodedBlockNum};

    SECTION("valid canonical head") {
        EXPECT_CALL(*mock_ro_cursor, to_last())
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{valid_block_num_slice, kValidBlockHashSlice, /*.done=*/true};
            }));
        CHECK(read_canonical_head(mock_ro_txn) == std::tuple<BlockNum, Hash>{2, kBlockHash});
    }
    SECTION("data not found") {
        EXPECT_CALL(*mock_ro_cursor, to_last())
            .WillOnce(InvokeWithoutArgs([]() mutable -> CursorResult {
                return CursorResult{::mdbx::slice{}, ::mdbx::slice{}, /*.done=*/false};
            }));
        CHECK(read_canonical_head(mock_ro_txn) == std::tuple<BlockNum, Hash>{});
    }
    SECTION("invalid key size") {
        EXPECT_CALL(*mock_ro_cursor, to_last())
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{invalid_block_num_slice, kValidBlockHashSlice, /*.done=*/true};
            }));
        CHECK_THROWS_AS(read_canonical_head(mock_ro_txn), std::length_error);
    }
    SECTION("invalid value size") {
        EXPECT_CALL(*mock_ro_cursor, to_last())
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{valid_block_num_slice, kInvalidBlockHashSlice, /*.done=*/true};
            }));
        CHECK_THROWS_AS(read_canonical_head(mock_ro_txn), std::length_error);
    }
}

TEST_CASE_METHOD(AccessLayerTest, "read_canonical_header_hash", "[db][access_layer]") {
    BlockNum block_num{2};
    const auto block_num_key{block_key(block_num)};
    const ::mdbx::slice block_key_slice{to_slice(block_num_key)};

    SECTION("valid canonical header hash") {
        EXPECT_CALL(*mock_ro_cursor, find(block_key_slice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{block_key_slice, kValidBlockHashSlice, /*.done=*/true};
            }));
        CHECK(read_canonical_header_hash(mock_ro_txn, block_num) == kBlockHash);
    }
    SECTION("data not found") {
        EXPECT_CALL(*mock_ro_cursor, find(block_key_slice, false))
            .WillOnce(InvokeWithoutArgs([]() mutable -> CursorResult {
                return CursorResult{::mdbx::slice{}, ::mdbx::slice{}, /*.done=*/false};
            }));
        CHECK_FALSE(read_canonical_header_hash(mock_ro_txn, block_num));
    }
    SECTION("invalid value size") {
        EXPECT_CALL(*mock_ro_cursor, find(block_key_slice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{block_key_slice, kInvalidBlockHashSlice, /*.done=*/true};
            }));
        CHECK_THROWS_AS(read_canonical_header_hash(mock_ro_txn, block_num), std::length_error);
    }
}

TEST_CASE_METHOD(AccessLayerTest, "read_block_by_number", "[db][access_layer]") {
    BlockNum block_num{2};
    const auto block_num_key{block_key(block_num)};
    const ::mdbx::slice block_key_slice{to_slice(block_num_key)};
    Block block;

    SECTION("data not found") {
        EXPECT_CALL(*mock_ro_cursor, find(block_key_slice, false))
            .WillOnce(InvokeWithoutArgs([]() mutable -> CursorResult {
                return CursorResult{::mdbx::slice{}, ::mdbx::slice{}, false};
            }));
        CHECK_FALSE(read_block_by_number(mock_ro_txn, block_num, /*read_senders=*/false, block));
    }
    SECTION("invalid value size") {
        EXPECT_CALL(*mock_ro_cursor, find(block_key_slice, false))
            .WillOnce(InvokeWithoutArgs([=]() mutable -> CursorResult {
                return CursorResult{block_key_slice, kInvalidBlockHashSlice, true};
            }));
        CHECK_THROWS_AS(read_block_by_number(mock_ro_txn, block_num, /*read_senders=*/false, block), std::length_error);
    }
}

}  // namespace silkworm::db
