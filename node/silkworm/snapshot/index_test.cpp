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

#include <utility>

#include <catch2/catch.hpp>

#include <silkworm/common/rlp_err.hpp>
#include <silkworm/test/log.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

TEST_CASE("Index::Index", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{"v1-014500-015000-headers.seg"};
    HeaderIndex header_index{*SnapshotFile::parse(tmp_snapshot_file.path().string())};
    CHECK_THROWS_AS(header_index.build(), std::logic_error);
}

TEST_CASE("TransactionIndex::build KO: empty snapshot", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    constexpr const char* kBodiesSnapshotFileName{"v1-014500-015000-bodies.seg"};
    constexpr const char* kTransactionsSnapshotFileName{"v1-014500-015000-transactions.seg"};

    SECTION("KO: empty body snapshot", "[.]") {
        test::TemporarySnapshotFile bodies_snapshot_file{kBodiesSnapshotFileName};
        test::TemporarySnapshotFile txs_snapshot_file{kTransactionsSnapshotFileName};
        TransactionIndex tx_index{*SnapshotFile::parse(txs_snapshot_file.path().string())};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }
}

//! Sample Bodies snapshot file: it contains body for block 1'500'013 on mainnet
class SampleBodySnapshotFile : public test::TemporarySnapshotFile {
  public:
    inline static constexpr const char* kBodiesSnapshotFileName{"v1-001500-001500-bodies.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    explicit SampleBodySnapshotFile(std::string_view hex)
        : TemporarySnapshotFile{kBodiesSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleBodySnapshotFile()
        : SampleBodySnapshotFile(
              "000000000000000e000000000000000000000000000000000000000000000004"  // WC=14 EWC=0 PATTERNS=0 POSITIONS=4
              "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, 00}, {01, 08}
              "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, c6837004d980c0}
              "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // ...
              "04d980c001c6837004d980c001c6837004d901c0"                          // {01, c6837004d901c0}
          ) {}
};

//! Sample Transactions snapshot file: it contains transactions for block 1'500'013 on mainnet (a block with 1 tx)
class SampleTransactionSnapshotFile : public test::TemporarySnapshotFile {
  public:
    inline static constexpr const char* kTransactionsSnapshotFileName{"v1-001500-001500-transactions.seg"};

    //! This ctor lets you pass any snapshot content and is used to produce broken snapshots
    explicit SampleTransactionSnapshotFile(std::string_view hex)
        : TemporarySnapshotFile{kTransactionsSnapshotFileName, *from_hex(hex)} {}

    //! This empty ctor captures the correct sample snapshot content once for all
    explicit SampleTransactionSnapshotFile()
        : SampleTransactionSnapshotFile(
              "0000000000000001000000000000000000000000000000000000000000000004"  // WC=1 EWC=0 PATTERNS=0 POSITIONS=4
              "0100017201f86f828f938504a817c80083015f9094e9ae6ec1117bbfeb89302c"  // {01, 00}, {01, 72}, {01, f86f...
              "e7e632597bc595efae880e61a774f297bb80801ca031131812a9b210cf6033e9"  // ...
              "420478b72f08251d8c7323dd88bd3a180679fa90b5a028a6d676d77923b19506"  // ...
              "c7aaae5f1dc2f2244855aabb6672401c1b55b0d844ff"                      // ...44ff}
          ) {}
};

//! Sample Transaction snapshot path injecting custom from/to blocks to override 500'000 block range
class SampleTransactionSnapshotPath : public test::TransactionSnapshotPath {
  public:
    explicit SampleTransactionSnapshotPath(std::filesystem::path path)
        : test::TransactionSnapshotPath(std::move(path), 1'500'000, 1'500'014) {}
};

TEST_CASE("TransactionIndex::build KO: invalid snapshot", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
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
        TransactionIndex tx_index{*SnapshotFile::parse(txs_snapshot_file.path().string())};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid position depth") {
        SampleBodySnapshotFile invalid_bodies_snapshot{
            "000000000000000e000000000000000000000000000000000000000000000004"
            "c100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {c1, 00} <- c1 instead of 01
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        SampleTransactionSnapshotFile valid_txs_snapshot{};
        SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid position value") {
        SampleBodySnapshotFile invalid_bodies_snapshot{
            "000000000000000e000000000000000000000000000000000000000000000004"
            "01ff010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"  // {01, ff} <- ff instead of 00
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        SampleTransactionSnapshotFile valid_txs_snapshot{};
        SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid positions count") {
        SampleBodySnapshotFile invalid_bodies_snapshot{
            "000000000000000e000000000000000000000000000000000000000000000005"  // POSITIONS=5 <- 5 instead of 4
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        SampleTransactionSnapshotFile valid_txs_snapshot{};
        SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }

    SECTION("KO: invalid RLP") {
        SampleBodySnapshotFile invalid_bodies_snapshot{
            "000000000000000e000000000000000000000000000000000000000000000004"
            "0100010801c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c78370"  // {01, c7837004d980c0} <- c7 instead of c6
            "04d980c001c6837004d980c001c6837004d980c001c6837004d980c001c68370"
            "04d980c001c6837004d980c001c6837004d901c0"};
        SampleTransactionSnapshotFile valid_txs_snapshot{};
        SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
        TransactionIndex tx_index{txs_snapshot_path};
        CHECK_THROWS_AS(tx_index.build(), rlp::DecodingError);
    }
}

TEST_CASE("TransactionIndex::build OK", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    SampleBodySnapshotFile valid_bodies_snapshot{};
    SampleTransactionSnapshotFile valid_txs_snapshot{};
    SampleTransactionSnapshotPath txs_snapshot_path{valid_txs_snapshot.path()};  // necessary to tweak the block numbers
    TransactionIndex tx_index{txs_snapshot_path};
    CHECK_NOTHROW(tx_index.build());
}

}  // namespace silkworm
