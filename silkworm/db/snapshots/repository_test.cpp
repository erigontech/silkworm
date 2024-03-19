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

#include "repository.hpp"

#include <catch2/catch.hpp>

#include <silkworm/db/snapshots/index.hpp>
#include <silkworm/db/snapshots/test_util/common.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

namespace test = test_util;
using silkworm::test_util::SetLogVerbosityGuard;

TEST_CASE("SnapshotRepository::SnapshotRepository", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    CHECK_NOTHROW(SnapshotRepository{SnapshotSettings{}});
}

TEST_CASE("SnapshotRepository::reopen_folder", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};

    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    test::TemporarySnapshotFile tmp_snapshot_1{tmp_dir, "v1-014500-015000-headers.seg"};
    test::TemporarySnapshotFile tmp_snapshot_2{tmp_dir, "v1-011500-012000-bodies.seg"};
    test::TemporarySnapshotFile tmp_snapshot_3{tmp_dir, "v1-015000-015500-transactions.seg"};
    SnapshotSettings settings{tmp_snapshot_1.path().parent_path()};
    SnapshotRepository repository{settings};
    CHECK_THROWS_AS(repository.reopen_folder(), std::logic_error);
    CHECK(repository.header_snapshots_count() == 0);
    CHECK(repository.body_snapshots_count() == 0);
    CHECK(repository.tx_snapshots_count() == 0);
    CHECK(repository.max_block_available() == 0);
}

TEST_CASE("SnapshotRepository::view", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    SnapshotSettings settings{tmp_dir};
    SnapshotRepository repository{settings};
    auto failing_walk = [](const auto&) { return false; };
    auto successful_walk = [](const auto&) { return true; };

    SECTION("no snapshots") {
        repository.reopen_folder();

        using ViewResult = SnapshotRepository::ViewResult;
        CHECK(repository.view_header_segment(14'500'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_body_segment(11'500'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_tx_segment(15'000'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_header_segments(successful_walk) == 0);
        CHECK(repository.view_body_segments(successful_walk) == 0);
        CHECK(repository.view_tx_segments(successful_walk) == 0);

        CHECK(repository.find_header_segment(14'500'000) == nullptr);
        CHECK(repository.find_body_segment(11'500'000) == nullptr);
        CHECK(repository.find_tx_segment(15'000'000) == nullptr);
    }

    SECTION("empty snapshots") {
        test::TemporarySnapshotFile tmp_snapshot_1{tmp_dir, "v1-014500-015000-headers.seg"};
        test::TemporarySnapshotFile tmp_snapshot_2{tmp_dir, "v1-011500-012000-bodies.seg"};
        test::TemporarySnapshotFile tmp_snapshot_3{tmp_dir, "v1-015000-015500-transactions.seg"};
        CHECK_THROWS_AS(repository.reopen_folder(), std::logic_error);

        using ViewResult = SnapshotRepository::ViewResult;
        CHECK(repository.view_header_segment(14'500'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_body_segment(11'500'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_tx_segment(15'000'000, successful_walk) == ViewResult::kSnapshotNotFound);
        CHECK(repository.view_header_segments(successful_walk) == 0);  // empty snapshots are ignored by repository
        CHECK(repository.view_body_segments(successful_walk) == 0);    // empty snapshots are ignored by repository
        CHECK(repository.view_tx_segments(successful_walk) == 0);      // empty snapshots are ignored by repository

        CHECK(repository.find_header_segment(14'500'000) == nullptr);
        CHECK(repository.find_body_segment(11'500'000) == nullptr);
        CHECK(repository.find_tx_segment(15'000'000) == nullptr);
    }

    SECTION("non-empty snapshots") {
        test::HelloWorldSnapshotFile tmp_snapshot_1{tmp_dir, "v1-014500-015000-headers.seg"};
        test::HelloWorldSnapshotFile tmp_snapshot_2{tmp_dir, "v1-011500-012000-bodies.seg"};
        test::HelloWorldSnapshotFile tmp_snapshot_3{tmp_dir, "v1-015000-015500-transactions.seg"};
        repository.reopen_folder();

        using ViewResult = SnapshotRepository::ViewResult;
        CHECK(repository.view_header_segment(14'500'000, failing_walk) == ViewResult::kWalkFailed);
        CHECK(repository.view_body_segment(11'500'000, failing_walk) == ViewResult::kWalkFailed);
        CHECK(repository.view_tx_segment(15'000'000, failing_walk) == ViewResult::kWalkFailed);
        CHECK(repository.view_header_segments(failing_walk) == 1);
        CHECK(repository.view_body_segments(failing_walk) == 1);
        CHECK(repository.view_tx_segments(failing_walk) == 1);

        CHECK(repository.view_header_segment(14'500'000, successful_walk) == ViewResult::kWalkSuccess);
        CHECK(repository.view_body_segment(11'500'000, successful_walk) == ViewResult::kWalkSuccess);
        CHECK(repository.view_tx_segment(15'000'000, successful_walk) == ViewResult::kWalkSuccess);
        CHECK(repository.view_header_segments(successful_walk) == 1);
        CHECK(repository.view_body_segments(successful_walk) == 1);
        CHECK(repository.view_tx_segments(successful_walk) == 1);

        // CHECK(repository.find_header_segment(14'500'000) != nullptr);  // needs index after check vs max_block_available
        // CHECK(repository.find_body_segment(11'500'000) != nullptr);
        // CHECK(repository.find_tx_segment(15'000'000) != nullptr);
    }
}

TEST_CASE("SnapshotRepository::missing_block_ranges", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    SnapshotSettings settings{tmp_dir};
    SnapshotRepository repository{settings};

    test::HelloWorldSnapshotFile tmp_snapshot_1{tmp_dir, "v1-014500-015000-headers.seg"};
    test::HelloWorldSnapshotFile tmp_snapshot_2{tmp_dir, "v1-011500-012000-bodies.seg"};
    test::HelloWorldSnapshotFile tmp_snapshot_3{tmp_dir, "v1-015000-015500-transactions.seg"};
    repository.reopen_folder();
    CHECK(repository.missing_block_ranges() == std::vector<BlockNumRange>{
                                                   BlockNumRange{0, 11'500'000},
                                                   BlockNumRange{12'000'000, 14'500'000}});
}

TEST_CASE("SnapshotRepository::find_segment", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    SnapshotSettings settings{tmp_dir};
    SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_snapshot{tmp_dir};
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};
    test::SampleTransactionSnapshotFile txn_snapshot{tmp_dir};

    SECTION("header w/o index") {
        CHECK(repository.find_header_segment(1'500'011) == nullptr);
        CHECK(repository.find_header_segment(1'500'012) == nullptr);
        CHECK(repository.find_header_segment(1'500'013) == nullptr);
        CHECK(repository.find_header_segment(1'500'014) == nullptr);
    }
    SECTION("body w/o index") {
        CHECK(repository.find_body_segment(1'500'011) == nullptr);
        CHECK(repository.find_body_segment(1'500'012) == nullptr);
        CHECK(repository.find_body_segment(1'500'013) == nullptr);
        CHECK(repository.find_body_segment(1'500'014) == nullptr);
    }
    SECTION("tx w/o index") {
        CHECK(repository.find_tx_segment(1'500'011) == nullptr);
        CHECK(repository.find_tx_segment(1'500'012) == nullptr);
        CHECK(repository.find_tx_segment(1'500'013) == nullptr);
        CHECK(repository.find_tx_segment(1'500'014) == nullptr);
    }

    test::SampleHeaderSnapshotPath header_snapshot_path{header_snapshot.path()};  // necessary to tweak the block numbers
    auto header_index = HeaderIndex::make(header_snapshot_path);
    REQUIRE_NOTHROW(header_index.build());
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};  // necessary to tweak the block numbers
    auto body_index = BodyIndex::make(body_snapshot_path);
    REQUIRE_NOTHROW(body_index.build());
    test::SampleTransactionSnapshotPath txn_snapshot_path{txn_snapshot.path()};  // necessary to tweak the block numbers
    REQUIRE_NOTHROW(TransactionIndex1::make(body_snapshot_path, txn_snapshot_path).build());
    REQUIRE_NOTHROW(TransactionToBlockIndex(body_snapshot_path, txn_snapshot_path).build());

    REQUIRE_NOTHROW(repository.reopen_folder());

    SECTION("header w/ index") {
        CHECK(repository.find_header_segment(1'500'011) == nullptr);
        // CHECK(repository.find_header_segment(1'500'012) != nullptr);  // needs full block number in snapshot file names
        // CHECK(repository.find_header_segment(1'500'013) != nullptr);  // needs full block number in snapshot file names
        CHECK(repository.find_header_segment(1'500'014) == nullptr);
    }
    SECTION("body w/ index") {
        CHECK(repository.find_body_segment(1'500'011) == nullptr);
        // CHECK(repository.find_body_segment(1'500'012) != nullptr);  // needs full block number in snapshot file names
        // CHECK(repository.find_body_segment(1'500'013) != nullptr);  // needs full block number in snapshot file names
        CHECK(repository.find_body_segment(1'500'014) == nullptr);
    }
    SECTION("tx w/ index") {
        CHECK(repository.find_tx_segment(1'500'011) == nullptr);
        // CHECK(repository.find_tx_segment(1'500'012) != nullptr);  // needs full block number in snapshot file names
        // CHECK(repository.find_tx_segment(1'500'013) != nullptr);  // needs full block number in snapshot file names
        CHECK(repository.find_tx_segment(1'500'014) == nullptr);
    }
    SECTION("greater than max_block_available") {
        CHECK(repository.find_body_segment(repository.max_block_available() + 1) == nullptr);
    }
}

TEST_CASE("SnapshotRepository::find_block_number", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    const auto tmp_dir = TemporaryDirectory::get_unique_temporary_path();
    std::filesystem::create_directories(tmp_dir);
    SnapshotSettings settings{tmp_dir};
    SnapshotRepository repository{settings};

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_snapshot{tmp_dir};
    test::SampleBodySnapshotFile body_snapshot{tmp_dir};
    test::SampleTransactionSnapshotFile txn_snapshot{tmp_dir};

    test::SampleHeaderSnapshotPath header_snapshot_path{header_snapshot.path()};  // necessary to tweak the block numbers
    auto header_index = HeaderIndex::make(header_snapshot_path);
    REQUIRE_NOTHROW(header_index.build());
    test::SampleBodySnapshotPath body_snapshot_path{body_snapshot.path()};  // necessary to tweak the block numbers
    auto body_index = BodyIndex::make(body_snapshot_path);
    REQUIRE_NOTHROW(body_index.build());
    test::SampleTransactionSnapshotPath txn_snapshot_path{txn_snapshot.path()};  // necessary to tweak the block numbers
    REQUIRE_NOTHROW(TransactionIndex1::make(body_snapshot_path, txn_snapshot_path).build());
    REQUIRE_NOTHROW(TransactionToBlockIndex(body_snapshot_path, txn_snapshot_path).build());

    REQUIRE_NOTHROW(repository.reopen_folder());

    // known block 1'500'012 txn hash
    auto block_number = repository.find_block_number(silkworm::Hash{from_hex("0x2224c39c930355233f11414e9f216f381c1f6b0c32fc77b192128571c2dc9eb9").value()});
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'012);

    // known block 1'500'012 txn hash
    block_number = repository.find_block_number(silkworm::Hash{from_hex("0x3ba9a1f95b96d0a43093b1ade1174133ea88ca395e60fe9fd8144098ff7a441f").value()});
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'013);

    // unknown txn hash
    block_number = repository.find_block_number(silkworm::Hash{from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").value()});
    // CHECK_FALSE(block_number.has_value());  // needs correct key check in index
}

}  // namespace silkworm::snapshots
