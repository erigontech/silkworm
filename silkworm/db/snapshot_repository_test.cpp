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

#include <chrono>
#include <filesystem>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/test_util/make_repository.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_queries.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots {

namespace test = test_util;
using db::test_util::make_repository;
using silkworm::test_util::SetLogVerbosityGuard;

#define CHECK_FIRST(x) CHECK((x).first)
#define CHECK_FALSE_FIRST(x) CHECK_FALSE((x).first)

TEST_CASE("SnapshotRepository::SnapshotRepository", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    CHECK_NOTHROW(make_repository(SnapshotSettings{}));
}

TEST_CASE("SnapshotRepository::reopen_folder.partial_bundle", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;

    test::TemporarySnapshotFile tmp_snapshot_1{tmp_dir.path(), "v1-014500-015000-headers.seg"};
    test::TemporarySnapshotFile tmp_snapshot_2{tmp_dir.path(), "v1-011500-012000-bodies.seg"};
    test::TemporarySnapshotFile tmp_snapshot_3{tmp_dir.path(), "v1-015000-015500-transactions.seg"};
    SnapshotSettings settings{tmp_dir.path()};
    auto repository = make_repository(settings);
    repository.reopen_folder();
    CHECK(repository.bundles_count() == 0);
    CHECK(repository.max_block_available() == 0);
}

TEST_CASE("SnapshotRepository::view", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;

    SnapshotSettings settings{tmp_dir.path()};
    auto repository = make_repository(settings);

    SECTION("no snapshots") {
        repository.reopen_folder();

        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 14'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 11'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 15'000'000));

        size_t bundles_count = 0;
        for ([[maybe_unused]] const auto& bundle : repository.view_bundles()) {
            ++bundles_count;
        }
        CHECK(bundles_count == 0);

        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 14'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 11'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 15'000'000));
    }

    SECTION("partial bundle") {
        test::TemporarySnapshotFile tmp_snapshot_1{tmp_dir.path(), "v1-014500-015000-headers.seg"};
        test::TemporarySnapshotFile tmp_snapshot_2{tmp_dir.path(), "v1-011500-012000-bodies.seg"};
        test::TemporarySnapshotFile tmp_snapshot_3{tmp_dir.path(), "v1-015000-015500-transactions.seg"};
        repository.reopen_folder();

        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 14'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 11'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 15'000'000));

        size_t bundles_count = 0;
        for ([[maybe_unused]] const auto& bundle : repository.view_bundles()) {
            ++bundles_count;
        }
        // empty snapshots are ignored by repository
        CHECK(bundles_count == 0);

        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 14'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 11'500'000));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 15'000'000));
    }

    SECTION("non-empty snapshots") {
        test::SampleHeaderSnapshotFile tmp_snapshot_1{tmp_dir.path()};
        test::SampleBodySnapshotFile tmp_snapshot_2{tmp_dir.path()};
        test::SampleTransactionSnapshotFile tmp_snapshot_3{tmp_dir.path()};

        for (auto& index_builder : repository.missing_indexes()) {
            index_builder->build();
        }

        repository.reopen_folder();

        size_t bundles_count = 0;
        for ([[maybe_unused]] const auto& bundle : repository.view_bundles()) {
            ++bundles_count;
        }
        CHECK(bundles_count == 1);

        CHECK_FIRST(repository.find_segment(SnapshotType::headers, 1'500'000));
        CHECK_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'000));
        CHECK_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'000));

        bundles_count = 0;
        for ([[maybe_unused]] const auto& bundle : repository.view_bundles()) {
            ++bundles_count;
        }
        CHECK(bundles_count == 1);
    }
}

TEST_CASE("SnapshotRepository::find_segment", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    SnapshotSettings settings{tmp_dir.path()};
    auto repository = make_repository(settings);

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_segment{tmp_dir.path()};
    test::SampleBodySnapshotFile body_segment{tmp_dir.path()};
    test::SampleTransactionSnapshotFile txn_segment{tmp_dir.path()};

    SECTION("header w/o index") {
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 1'500'011));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 1'500'012));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 1'500'013));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::headers, 1'500'014));
    }
    SECTION("body w/o index") {
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'011));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'012));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'013));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'014));
    }
    SECTION("tx w/o index") {
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'011));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'012));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'013));
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'014));
    }

    auto header_index = HeaderIndex::make(header_segment.path());
    header_index.set_base_data_id(header_segment.block_num_range().start);
    REQUIRE_NOTHROW(header_index.build());
    auto& body_segment_path = body_segment.path();
    auto body_index = BodyIndex::make(body_segment_path);
    body_index.set_base_data_id(body_segment.block_num_range().start);
    REQUIRE_NOTHROW(body_index.build());
    auto& txn_segment_path = txn_segment.path();
    REQUIRE_NOTHROW(TransactionIndex::make(body_segment_path, txn_segment_path).build());
    REQUIRE_NOTHROW(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment.block_num_range().start).build());

    REQUIRE_NOTHROW(repository.reopen_folder());

    SECTION("header w/ index") {
        CHECK_FIRST(repository.find_segment(SnapshotType::headers, 1'500'011));
        CHECK_FIRST(repository.find_segment(SnapshotType::headers, 1'500'012));
        CHECK_FIRST(repository.find_segment(SnapshotType::headers, 1'500'013));
        CHECK_FIRST(repository.find_segment(SnapshotType::headers, 1'500'014));
    }
    SECTION("body w/ index") {
        CHECK_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'011));
        CHECK_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'012));
        CHECK_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'013));
        CHECK_FIRST(repository.find_segment(SnapshotType::bodies, 1'500'014));
    }
    SECTION("tx w/ index") {
        CHECK_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'011));
        CHECK_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'012));
        CHECK_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'013));
        CHECK_FIRST(repository.find_segment(SnapshotType::transactions, 1'500'014));
    }
    SECTION("greater than max_block_available") {
        CHECK_FALSE_FIRST(repository.find_segment(SnapshotType::bodies, repository.max_block_available() + 1));
    }
}

TEST_CASE("SnapshotRepository::find_block_number", "[silkworm][node][snapshot]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    SnapshotSettings settings{tmp_dir.path()};
    auto repository = make_repository(settings);

    // These sample snapshot files just contain data for block range [1'500'012, 1'500'013], hence current snapshot
    // file name format is not sufficient to support them (see checks commented out below)
    test::SampleHeaderSnapshotFile header_segment{tmp_dir.path()};
    test::SampleBodySnapshotFile body_segment{tmp_dir.path()};
    test::SampleTransactionSnapshotFile txn_segment{tmp_dir.path()};

    auto header_index = HeaderIndex::make(header_segment.path());
    header_index.set_base_data_id(header_segment.block_num_range().start);
    REQUIRE_NOTHROW(header_index.build());
    auto& body_segment_path = body_segment.path();
    auto body_index = BodyIndex::make(body_segment_path);
    body_index.set_base_data_id(body_segment.block_num_range().start);
    REQUIRE_NOTHROW(body_index.build());
    auto& txn_segment_path = txn_segment.path();
    REQUIRE_NOTHROW(TransactionIndex::make(body_segment_path, txn_segment_path).build());
    REQUIRE_NOTHROW(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment.block_num_range().start).build());

    REQUIRE_NOTHROW(repository.reopen_folder());

    TransactionBlockNumByTxnHashRepoQuery query{repository.view_bundles_reverse()};

    // known block 1'500'012 txn hash
    auto block_number = query.exec(silkworm::Hash{from_hex("0x2224c39c930355233f11414e9f216f381c1f6b0c32fc77b192128571c2dc9eb9").value()});
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'012);

    // known block 1'500'012 txn hash
    block_number = query.exec(silkworm::Hash{from_hex("0x3ba9a1f95b96d0a43093b1ade1174133ea88ca395e60fe9fd8144098ff7a441f").value()});
    CHECK(block_number.has_value());
    CHECK(block_number.value() == 1'500'013);

    // unknown txn hash
    block_number = query.exec(silkworm::Hash{from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").value()});
    // CHECK_FALSE(block_number.has_value());  // needs correct key check in index
}

static auto move_last_write_time(const std::filesystem::path& p, const std::filesystem::file_time_type::duration& d) {
    const auto ftime = std::filesystem::last_write_time(p);
    std::filesystem::last_write_time(p, ftime + d);
    return std::filesystem::last_write_time(p) - ftime;
}

TEST_CASE("SnapshotRepository::remove_stale_indexes", "[silkworm][node][snapshot][index]") {
    using namespace std::chrono_literals;

    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    SnapshotSettings settings{tmp_dir.path()};
    auto repository = make_repository(settings);

    // create a snapshot file
    test::SampleHeaderSnapshotFile header_segment_file{tmp_dir.path()};
    auto& header_segment_path = header_segment_file.path();

    // build an index
    auto index_builder = HeaderIndex::make(header_segment_path);
    index_builder.set_base_data_id(header_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(index_builder.build());
    auto index_path = index_builder.path().path();

    // the index is not stale
    repository.remove_stale_indexes();
    CHECK(std::filesystem::exists(index_path));

    // move the snapshot last write time 1 hour to the future to make its index "stale"
    const auto last_write_time_diff = move_last_write_time(header_segment_path.path(), 1h);
    CHECK((last_write_time_diff.count() > 0));

    // the index is stale
    repository.remove_stale_indexes();
    CHECK_FALSE(std::filesystem::exists(index_path));
}

}  // namespace silkworm::snapshots
