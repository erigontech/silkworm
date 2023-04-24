/*
   Copyright 2023 The Silkworm Authors

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

#include "snapshot_options.hpp"

namespace silkworm::cmd::common {

void add_snapshot_options(CLI::App& cli, snapshot::SnapshotSettings& snapshot_settings) {
    cli.add_flag("--snapshots.enabled", snapshot_settings.enabled,
                 "Flag indicating if usage of snapshots should be enabled or disable");
    cli.add_flag("--snapshots.no_downloader", snapshot_settings.no_downloader,
                 "If set, the snapshot downloader is disabled and just already present local snapshots are used");

    // TODO(canepat) add options for the other snapshot settings and for all bittorrent settings
}

}  // namespace silkworm::cmd::common
