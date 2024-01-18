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

#include "sync.hpp"

#include <catch2/catch.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/infra/test_util/temporary_file.hpp>
#include <silkworm/node/test/context.hpp>

namespace silkworm::snapshots {

TEST_CASE("SnapshotSync::SnapshotSync", "[silkworm][snapshot][sync]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    SnapshotRepository repository{SnapshotSettings{}};
    CHECK_NOTHROW(SnapshotSync{&repository, kMainnetConfig});
}

TEST_CASE("SnapshotSync::download_and_index_snapshots", "[silkworm][snapshot][sync]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    test::Context context;
    const auto tmp_dir{TemporaryDirectory::get_unique_temporary_path()};
    bittorrent::BitTorrentSettings bittorrent_settings{
        .repository_path = tmp_dir / bittorrent::BitTorrentSettings::kDefaultTorrentRepoPath,
    };

    SECTION("snapshots disabled") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir,
            .enabled = false,
            .bittorrent_settings = bittorrent_settings,
        };
        SnapshotRepository repository{settings};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }

    SECTION("no download, just reopen") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir,
            .no_downloader = true,
            .bittorrent_settings = bittorrent_settings,
        };
        SnapshotRepository repository{settings};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }

    SECTION("no download, just reopen and verify") {
        SnapshotSettings settings{
            .repository_dir = tmp_dir,
            .no_downloader = true,
            .bittorrent_settings = bittorrent_settings,
        };
        settings.bittorrent_settings.verify_on_startup = true;
        SnapshotRepository repository{settings};
        SnapshotSync sync{&repository, kMainnetConfig};
        CHECK(sync.download_and_index_snapshots(context.rw_txn()));
    }
}

}  // namespace silkworm::snapshots
