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

#include "snapshot_sync.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/blocks/bodies/body_index.hpp>
#include <silkworm/db/blocks/headers/header_index.hpp>
#include <silkworm/db/snapshot_bundle_factory_impl.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/db/transactions/txn_index.hpp>
#include <silkworm/db/transactions/txn_to_block_index.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::db {

using namespace snapshots;
using namespace silkworm::test_util;

static std::unique_ptr<SnapshotBundleFactory> bundle_factory() {
    return std::make_unique<db::SnapshotBundleFactoryImpl>();
}

TEST_CASE("SnapshotSync::SnapshotSync", "[db][snapshot][sync]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    SnapshotSettings settings{
        .bittorrent_settings = bittorrent::BitTorrentSettings{
            .repository_path = tmp_dir.path() / bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath,
        },
    };
    SnapshotRepository repository{settings, bundle_factory()};
    CHECK_NOTHROW(SnapshotSync{&repository, kMainnetConfig});
}

TEST_CASE("SnapshotSync::download_and_index_snapshots", "[db][snapshot][sync]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    db::test_util::TempChainData context;
    TemporaryDirectory tmp_dir;
    bittorrent::BitTorrentSettings bittorrent_settings{
        .repository_path = tmp_dir.path() / bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath,
    };

    SECTION("snapshots disabled") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir.path(),
            .enabled = false,
            .bittorrent_settings = bittorrent_settings,
        };
        SnapshotRepository repository{settings, bundle_factory()};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }

    SECTION("no download, just reopen") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir.path(),
            .no_downloader = true,
            .bittorrent_settings = bittorrent_settings,
        };
        SnapshotRepository repository{settings, bundle_factory()};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }

    SECTION("no download, just reopen and verify") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir.path(),
            .no_downloader = true,
            .bittorrent_settings = bittorrent_settings,
        };
        settings.bittorrent_settings.verify_on_startup = true;
        SnapshotRepository repository{settings, bundle_factory()};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }
}

struct SnapshotSyncForTest : public SnapshotSync {
    using SnapshotSync::build_missing_indexes;
    using SnapshotSync::SnapshotSync;
    using SnapshotSync::update_block_bodies;
    using SnapshotSync::update_block_hashes;
    using SnapshotSync::update_block_headers;
    using SnapshotSync::update_block_senders;
    using SnapshotSync::update_database;
};

TEST_CASE("SnapshotSync::update_block_headers", "[db][snapshot][sync]") {
    SetLogVerbosityGuard guard{log::Level::kNone};
    TemporaryDirectory tmp_dir;
    SnapshotSettings settings{
        .repository_dir = tmp_dir.path(),
        .bittorrent_settings = bittorrent::BitTorrentSettings{
            .repository_path = tmp_dir.path() / bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath,
        },
    };
    SnapshotRepository repository{settings, bundle_factory()};
    db::test_util::TempChainData tmp_db;

    // Create a sample Header snapshot+index
    snapshots::test_util::SampleHeaderSnapshotFile header_snapshot_file{tmp_dir.path()};
    snapshots::test_util::SampleHeaderSnapshotPath header_snapshot_path{header_snapshot_file.path()};
    snapshots::Snapshot header_snapshot{header_snapshot_path};
    REQUIRE_NOTHROW(snapshots::HeaderIndex::make(header_snapshot_path).build());
    snapshots::Index idx_header_hash{header_snapshot_path.index_file()};

    // Create a sample Body snapshot+index
    snapshots::test_util::SampleBodySnapshotFile body_snapshot_file{tmp_dir.path()};
    snapshots::test_util::SampleBodySnapshotPath body_snapshot_path{body_snapshot_file.path()};
    snapshots::Snapshot body_snapshot{body_snapshot_path};
    REQUIRE_NOTHROW(snapshots::BodyIndex::make(body_snapshot_path).build());
    snapshots::Index idx_body_number{body_snapshot_path.index_file()};

    // Create a sample Transaction snapshot+indexes
    snapshots::test_util::SampleTransactionSnapshotFile txn_snapshot_file{tmp_dir.path()};
    snapshots::test_util::SampleTransactionSnapshotPath txn_snapshot_path{txn_snapshot_file.path()};
    snapshots::Snapshot txn_snapshot{txn_snapshot_path};
    REQUIRE_NOTHROW(snapshots::TransactionIndex::make(body_snapshot_path, txn_snapshot_path).build());
    REQUIRE_NOTHROW(snapshots::TransactionToBlockIndex::make(body_snapshot_path, txn_snapshot_path).build());
    snapshots::Index idx_txn_hash{txn_snapshot_path.index_file_for_type(snapshots::SnapshotType::transactions)};
    snapshots::Index idx_txn_hash_2_block{txn_snapshot_path.index_file_for_type(snapshots::SnapshotType::transactions_to_block)};

    // Add a sample Snapshot bundle to the repository
    snapshots::SnapshotBundle bundle{
        .header_snapshot = std::move(header_snapshot),
        .idx_header_hash = std::move(idx_header_hash),

        .body_snapshot = std::move(body_snapshot),
        .idx_body_number = std::move(idx_body_number),

        .txn_snapshot = std::move(txn_snapshot),
        .idx_txn_hash = std::move(idx_txn_hash),
        .idx_txn_hash_2_block = std::move(idx_txn_hash_2_block),
    };
    repository.add_snapshot_bundle(std::move(bundle));

    // Update the block headers in the database according to the repository content
    SnapshotSyncForTest snapshot_sync{&repository, kMainnetConfig};
    CHECK_NOTHROW(snapshot_sync.update_block_headers(tmp_db.rw_txn(), repository.max_block_available()));

    // Expect that the database is correctly populated (N.B. cannot check Difficulty table because of sample snapshots)
    auto block_is_in_header_numbers = [&](Hash block_hash, BlockNum expected_block_number) {
        const auto block_number = db::read_block_number(tmp_db.rw_txn(), block_hash);
        return block_number == expected_block_number;
    };
    auto block_is_canonical = [&](BlockNum block_number, Hash expected_block_hash) {
        const auto canonical_block_hash = db::read_canonical_header_hash(tmp_db.rw_txn(), block_number);
        return canonical_block_hash == expected_block_hash;
    };

    const Hash block_1500013_hash{0xbef48d7de01f2d7ea1a7e4d1ed401f73d6d0257a364f6770b25ba51a123ac35f_bytes32};
    CHECK(block_is_in_header_numbers(block_1500013_hash, 1'500'013));
    CHECK(block_is_canonical(1'500'013, block_1500013_hash));
}

}  // namespace silkworm::db
