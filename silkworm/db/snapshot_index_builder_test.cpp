// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

namespace test = test_util;
using namespace Catch::Matchers;

TEST_CASE("Index::Index", "[silkworm][snapshot][index]") {
    TemporaryDirectory tmp_dir;
    test::TemporarySnapshotFile tmp_snapshot_file{tmp_dir.path(), "v1-014500-015000-headers.seg"};
    auto header_index = HeaderIndex::make(tmp_snapshot_file.path());
    CHECK_THROWS_AS(header_index.build(), std::logic_error);
}

// This unit test fails on Windows with error: SIGSEGV - Segmentation violation signal
TEST_CASE("BodyIndex::build OK", "[silkworm][snapshot][index]") {
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_segment_file{tmp_dir.path()};
    auto body_index = BodyIndex::make(body_segment_file.path());
    body_index.set_base_data_id(body_segment_file.block_num_range().start);
    CHECK_NOTHROW(body_index.build());
}

TEST_CASE("TransactionIndex::build KO: empty snapshot", "[silkworm][snapshot][index]") {
    TemporaryDirectory tmp_dir;
    constexpr const char* kBodiesSnapshotFileName{"v1-014500-015000-bodies.seg"};
    constexpr const char* kTransactionsSnapshotFileName{"v1-014500-015000-transactions.seg"};

    SECTION("KO: empty body snapshot", "[.]") {
        test::TemporarySnapshotFile body_segment_file{tmp_dir.path(), kBodiesSnapshotFileName};
        test::TemporarySnapshotFile txn_segment_file{tmp_dir.path(), kTransactionsSnapshotFileName};

        auto& txn_segment_path = txn_segment_file.path();
        auto& body_segment_path = body_segment_file.path();

        CHECK_THROWS_WITH(TransactionIndex::make(body_segment_path, txn_segment_path).build(), ContainsSubstring("empty body snapshot"));
        CHECK_THROWS_WITH(TransactionToBlockIndex::make(body_segment_path, txn_segment_path).build(), ContainsSubstring("empty body snapshot"));
    }
}

TEST_CASE("TransactionIndex::build KO: invalid snapshot", "[silkworm][snapshot][index]") {
    TemporaryDirectory tmp_dir;
    constexpr const char* kTransactionsSnapshotFileName{"v1-015000-015500-transactions.seg"};

    SECTION("KO: invalid zero word length") {
        test::TemporarySnapshotFile body_segment_file{
            tmp_dir.path(),
            "v1-015000-015500-bodies.seg",
            test::SnapshotHeader{
                .words_count = 7,
                .empty_words_count = 0,
                .patterns = {},
                .positions = {}},
            test::SnapshotBody{
                *from_hex("0000000000000000")}};
        test::TemporarySnapshotFile txn_segment_file{tmp_dir.path(), kTransactionsSnapshotFileName};

        auto& txn_segment_path = txn_segment_file.path();
        auto& body_segment_path = body_segment_file.path();

        CHECK_THROWS_WITH(TransactionIndex::make(body_segment_path, txn_segment_path).build(), StartsWith("invalid zero word length"));
        CHECK_THROWS_WITH(TransactionToBlockIndex::make(body_segment_path, txn_segment_path).build(), StartsWith("invalid zero word length"));
    }

    SECTION("KO: invalid position depth") {
        test::SampleBodySnapshotFile body_segment_file{
            tmp_dir.path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "c100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {c1, 00} <- c1 instead of 01
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        auto& body_segment_path = body_segment_file.path();
        test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
        auto& txn_segment_path = txn_segment_file.path();

        CHECK_THROWS_WITH(TransactionIndex::make(body_segment_path, txn_segment_path).build(), ContainsSubstring("invalid: position depth"));
        CHECK_THROWS_WITH(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start).build(), ContainsSubstring("invalid: position depth"));
    }

    SECTION("KO: invalid position value") {
        test::SampleBodySnapshotFile body_segment_file{
            tmp_dir.path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "01ff010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, ff} <- ff instead of 00
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        auto& body_segment_path = body_segment_file.path();
        test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
        auto& txn_segment_path = txn_segment_file.path();

        CHECK_THROWS_WITH(TransactionIndex::make(body_segment_path, txn_segment_path).build(), ContainsSubstring("invalid: position read"));
        CHECK_THROWS_WITH(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start).build(), ContainsSubstring("invalid: position read"));
    }

    SECTION("KO: invalid positions count") {
        test::SampleBodySnapshotFile body_segment_file{
            tmp_dir.path(),
            "000000000000000e000000000000000000000000000000000000000000000005"  // POSITIONS=5 <- 5 instead of 4
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        auto& body_segment_path = body_segment_file.path();
        test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
        auto& txn_segment_path = txn_segment_file.path();

        CHECK_THROWS_WITH(TransactionIndex::make(body_segment_path, txn_segment_path).build(), ContainsSubstring("invalid: position read"));
        CHECK_THROWS_WITH(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start).build(), ContainsSubstring("invalid: position read"));
    }

    SECTION("KO: invalid RLP") {
        test::SampleBodySnapshotFile body_segment_file{
            tmp_dir.path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c7837004d901c0"};  // {01, c7837004d980c0} <- c7 instead of c6
        auto& body_segment_path = body_segment_file.path();
        test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
        auto& txn_segment_path = txn_segment_file.path();

        CHECK_THROWS_AS(TransactionIndex::make(body_segment_path, txn_segment_path).build(), DecodingException);
        CHECK_THROWS_AS(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start).build(), DecodingException);
    }

    SECTION("KO: unexpected tx amount") {
        test::SampleBodySnapshotFile body_segment_file{tmp_dir.path()};
        auto& body_segment_path = body_segment_file.path();
        test::SampleTransactionSnapshotFile txn_segment_file{
            tmp_dir.path(),
            "000000000000000C"                              // WC = 12
            "0000000000000004"                              // EWC = 4
            "0000000000000000"                              // PaTS = 0
            "0000000000000016"                              // PoTS = 22
            "010004E60304850104E5020487010301048801048401"  // PoT = 0x01...01
            "0309"
            "3DE6BF8FE3E608CC04681B3DFC8B2D52AB94C23DB7F86D018504E3B292008252"  // Txn position 0 block 1'500'012 START
            "0894BB9BC244D798123FDE783FCC1C72D3BB8C1894138902292B2AD00B120000"
            "801CA0F5D7EB932991DC38FB5A3ED2ABCC71C2ABFC098BB2A9A25552ABEC2249"
            "A6AAF8A055CAD62B0CD8E2B6154F2EA52D308535EF634D9A207571996754A02E"
            "59DE97C1"  // Txn position 0 block 1'500'012 END
            // 11 txs missing here...
        };
        auto& txn_segment_path = txn_segment_file.path();

        auto tx_index = TransactionIndex::make(body_segment_path, txn_segment_path);
        CHECK_THROWS_WITH(tx_index.build(), StartsWith("keys expected"));
        auto tx_index_hash_to_block = TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start);
        CHECK_THROWS_WITH(tx_index_hash_to_block.build(), ContainsSubstring("tx count mismatch"));
    }
}

TEST_CASE("TransactionIndex::build OK", "[silkworm][snapshot][index]") {
    TemporaryDirectory tmp_dir;
    test::SampleBodySnapshotFile body_segment_file{tmp_dir.path()};
    auto& body_segment_path = body_segment_file.path();
    test::SampleTransactionSnapshotFile txn_segment_file{tmp_dir.path()};
    auto& txn_segment_path = txn_segment_file.path();

    auto tx_index = TransactionIndex::make(body_segment_path, txn_segment_path);
    tx_index.build();
    auto tx_index_hash_to_block = TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start);
    tx_index_hash_to_block.build();
}

}  // namespace silkworm::snapshots
