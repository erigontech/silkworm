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
#include <silkworm/db/blocks/transactions/txn_index.hpp>
#include <silkworm/db/blocks/transactions/txn_to_block_index.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/db/test_util/temp_snapshots.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/task_runner.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>

namespace silkworm::db {

using namespace snapshots;
using namespace silkworm::test_util;

struct SettingsOverrides {
    bool enabled{true};
    bool no_downloader{false};
};

class NoopStageSchedulerAdapter : public datastore::StageScheduler {
  public:
    explicit NoopStageSchedulerAdapter() = default;
    ~NoopStageSchedulerAdapter() override = default;
    Task<void> schedule(std::function<void(db::RWTxn&)> /*callback*/) override {
        co_return;
    }
};

struct SnapshotSyncTest {
    db::test_util::TempChainDataStore context;
    TaskRunner runner;
    NoopStageSchedulerAdapter stage_scheduler;
};

struct SnapshotSyncForTest : public SnapshotSync {
    using SnapshotSync::blocks_repository;
    using SnapshotSync::build_missing_indexes;
    using SnapshotSync::download_snapshots_if_needed;
    using SnapshotSync::update_block_bodies;
    using SnapshotSync::update_block_hashes;
    using SnapshotSync::update_block_headers;
    using SnapshotSync::update_block_senders;
    using SnapshotSync::update_database;

    static SnapshotSettings make_settings(
        const std::filesystem::path& tmp_dir_path,
        const SettingsOverrides& overrides) {
        return SnapshotSettings{
            .repository_path = tmp_dir_path,
            .enabled = overrides.enabled,
            .no_downloader = overrides.no_downloader,
            .bittorrent_settings = bittorrent::BitTorrentSettings{
                .repository_path = tmp_dir_path / bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath,
            },
        };
    }

    explicit SnapshotSyncForTest(SnapshotSyncTest& test, SettingsOverrides overrides = {})
        : SnapshotSync{
              make_settings(test.context.dir().snapshots().path(), overrides),
              kMainnetConfig.chain_id,
              test.context->ref(),
              test.context.dir().temp().path(),
              test.stage_scheduler} {}
};

TEST_CASE("SnapshotSync::SnapshotSync", "[db][snapshot][sync]") {
    SnapshotSyncTest test;
    CHECK_NOTHROW(SnapshotSyncForTest{test});
}

TEST_CASE("SnapshotSync::download_and_index_snapshots", "[db][snapshot][sync]") {
    SnapshotSyncTest test;

    SECTION("snapshots disabled") {
        SnapshotSyncForTest sync{test, SettingsOverrides{.enabled = false}};
        test.runner.run(sync.download_snapshots_if_needed());
    }

    SECTION("no download, just reopen") {
        SnapshotSyncForTest sync{test, SettingsOverrides{.no_downloader = true}};
        test.runner.run(sync.download_snapshots_if_needed());
    }
}

TEST_CASE("SnapshotSync::update_block_headers", "[db][snapshot][sync]") {
    SnapshotSyncTest test;
    SnapshotSyncForTest snapshot_sync{test};
    auto tmp_dir_path = test.context.dir().snapshots().path();

    // Create a sample Header snapshot+index
    snapshots::test_util::SampleHeaderSnapshotFile header_segment_file{tmp_dir_path};
    auto& header_segment_path = header_segment_file.path();
    auto header_index_builder = HeaderIndex::make(header_segment_path);
    header_index_builder.set_base_data_id(header_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(header_index_builder.build());

    // Create a sample Body snapshot+index
    snapshots::test_util::SampleBodySnapshotFile body_segment_file{tmp_dir_path};
    auto& body_segment_path = body_segment_file.path();
    auto body_index_builder = BodyIndex::make(body_segment_path);
    body_index_builder.set_base_data_id(body_segment_file.block_num_range().start);
    REQUIRE_NOTHROW(body_index_builder.build());

    // Create a sample Transaction snapshot+indexes
    snapshots::test_util::SampleTransactionSnapshotFile txn_segment_file{tmp_dir_path};
    auto& txn_segment_path = txn_segment_file.path();
    REQUIRE_NOTHROW(TransactionIndex::make(body_segment_path, txn_segment_path).build());
    REQUIRE_NOTHROW(TransactionToBlockIndex::make(body_segment_path, txn_segment_path, txn_segment_file.block_num_range().start).build());

    // Add a sample Snapshot bundle to the repository
    auto step_range = datastore::StepRange::from_block_num_range(snapshots::test_util::kSampleSnapshotBlockRange);
    auto& repository = snapshot_sync.blocks_repository();
    SnapshotBundle bundle = repository.open_bundle(step_range);
    repository.add_snapshot_bundle(std::move(bundle));

    // Update the block headers in the database according to the repository content
    auto& tmp_db = test.context;
    BlockNum max_block_available = header_segment_file.block_num_range().end - 1;
    auto is_stopping = [] { return false; };
    CHECK_NOTHROW(snapshot_sync.update_block_headers(tmp_db.rw_txn(), max_block_available, is_stopping));

    // Expect that the database is correctly populated (N.B. cannot check Difficulty table because of sample snapshots)
    auto block_is_in_header_numbers = [&](Hash block_hash, BlockNum expected_block_num) {
        const auto block_num = db::read_block_num(tmp_db.rw_txn(), block_hash);
        return block_num == expected_block_num;
    };
    auto block_is_canonical = [&](BlockNum block_num, Hash expected_block_hash) {
        const auto canonical_block_hash = db::read_canonical_header_hash(tmp_db.rw_txn(), block_num);
        return canonical_block_hash == expected_block_hash;
    };

    const Hash block_1500013_hash{0xbef48d7de01f2d7ea1a7e4d1ed401f73d6d0257a364f6770b25ba51a123ac35f_bytes32};
    CHECK(block_is_in_header_numbers(block_1500013_hash, 1'500'013));
    CHECK(block_is_canonical(1'500'013, block_1500013_hash));
}

}  // namespace silkworm::db
