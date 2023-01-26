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

#include <silkworm/test/log.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

TEST_CASE("Index::Index", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{"v1-014500-015000-headers.seg"};
    HeaderIndex header_index{*SnapshotFile::parse(tmp_snapshot_file.path().string())};
    CHECK_THROWS_AS(header_index.build(), std::logic_error);
}

TEST_CASE("TransactionIndex::build KO: empty body snapshot", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    constexpr const char* kBodiesSnapshotFileName{"v1-014500-015000-bodies.seg"};
    constexpr const char* kTransactionsSnapshotFileName{"v1-014500-015000-transactions.seg"};

    SECTION("KO: empty snapshots", "[.]") {
        test::TemporarySnapshotFile bodies_snapshot_file{kBodiesSnapshotFileName};
        test::TemporarySnapshotFile txs_snapshot_file{kTransactionsSnapshotFileName};
        TransactionIndex tx_index{*SnapshotFile::parse(txs_snapshot_file.path().string())};
        CHECK_THROWS_AS(tx_index.build(), std::runtime_error);
    }
}

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
}

}  // namespace silkworm
