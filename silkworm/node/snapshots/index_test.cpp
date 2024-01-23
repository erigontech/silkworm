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

#include "index.hpp"

#include <catch2/catch.hpp>

#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/snapshots/test_util/common.hpp>

namespace silkworm::snapshots {

namespace test = test_util;
using silkworm::test_util::SetLogVerbosityGuard;

TEST_CASE("Index::Index", "[silkworm][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{"v1-014500-015000-headers.seg"};
    HeaderIndex header_index{*SnapshotPath::parse(tmp_snapshot_file.path().string())};
    CHECK_THROWS_AS(header_index.build(), std::logic_error);
}

// This unit test fails on Windows with error: SIGSEGV - Segmentation violation signal
TEST_CASE("BodyIndex::build OK", "[silkworm][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleBodySnapshotFile valid_body_snapshot{};
    test::SampleBodySnapshotPath body_snapshot_path{valid_body_snapshot.path()};  // necessary to tweak the block numbers
    BodyIndex body_index{body_snapshot_path};
    CHECK_NOTHROW(body_index.build());
}

TEST_CASE("TransactionIndex::build KO: empty snapshot", "[silkworm][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    constexpr const char* kBodiesSnapshotFileName{"v1-014500-015000-bodies.seg"};
    constexpr const char* kTransactionsSnapshotFileName{"v1-014500-015000-transactions.seg"};

    SECTION("KO: empty body snapshot", "[.]") {
        test::TemporarySnapshotFile bodies_snapshot_file{kBodiesSnapshotFileName};
        test::TemporarySnapshotFile txs_snapshot_file{kTransactionsSnapshotFileName};
        TransactionIndex tx_index{*SnapshotPath::parse(txs_snapshot_file.path().string())};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }
}

TEST_CASE("TransactionIndex::build KO: invalid snapshot", "[silkworm][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    constexpr const char* kTransactionsSnapshotFileName{"v1-015000-015500-transactions.seg"};

    SECTION("KO: invalid zero word length") {
        test::TemporarySnapshotFile bodies_snapshot_file{
            "v1-015000-015500-bodies.seg",
            test::SnapshotHeader{
                .words_count = 0,
                .empty_words_count = 0,
                .patterns = {},
                .positions = {}},
            test::SnapshotBody{
                *from_hex("0000000000000000")}};
        test::TemporarySnapshotFile txs_snapshot_file{kTransactionsSnapshotFileName};
        TransactionIndex tx_index{*SnapshotPath::parse(txs_snapshot_file.path().string())};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid position depth") {
        test::SampleBodySnapshotFile invalid_bodies_snapshot{
            TemporaryDirectory::get_os_temporary_path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "c100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {c1, 00} <- c1 instead of 01
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        test::SampleTransactionSnapshotFile valid_txs_snapshot{};
        test::SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid position value") {
        test::SampleBodySnapshotFile invalid_bodies_snapshot{
            TemporaryDirectory::get_os_temporary_path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "01ff010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, ff} <- ff instead of 00
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        test::SampleTransactionSnapshotFile valid_txs_snapshot{};
        test::SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid positions count") {
        test::SampleBodySnapshotFile invalid_bodies_snapshot{
            TemporaryDirectory::get_os_temporary_path(),
            "000000000000000e000000000000000000000000000000000000000000000005"  // POSITIONS=5 <- 5 instead of 4
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        test::SampleTransactionSnapshotFile valid_txs_snapshot{};
        test::SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid RLP") {
        test::SampleBodySnapshotFile invalid_bodies_snapshot{
            TemporaryDirectory::get_os_temporary_path(),
            "000000000000000e000000000000000000000000000000000000000000000004"
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c78370"  // {01, c7837004d980c0} <- c7 instead of c6
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        test::SampleTransactionSnapshotFile valid_txs_snapshot{};
        test::SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), DecodingException);
    }
}

TEST_CASE("TransactionIndex::build OK", "[silkworm][snapshot][index]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleBodySnapshotFile valid_bodies_snapshot{};
    test::SampleTransactionSnapshotFile valid_txs_snapshot{};
    test::SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{txs_snapshot_path};
    CHECK_NOTHROW(tx_index.build());
}

}  // namespace silkworm::snapshots
