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

void add_snapshot_options(CLI::App& cli, snapshots::SnapshotSettings& snapshot_settings) {
    cli.add_flag("--snapshots.enabled", snapshot_settings.enabled)
        ->description("Flag indicating if usage of snapshots should be enabled or disable")
        ->capture_default_str();
    cli.add_flag("--snapshots.no_downloader", snapshot_settings.no_downloader)
        ->description("If set, the snapshot downloader is disabled and just already present local snapshots are used")
        ->capture_default_str();
    cli.add_option("--snapshots.repository.path", snapshot_settings.repository_dir)
        ->description("Filesystem path where snapshots will be stored")
        ->capture_default_str();

    // TODO(canepat) add options for the other snapshot settings and for all bittorrent settings
    cli.add_option("--torrent.verify_on_startup", snapshot_settings.bittorrent_settings.verify_on_startup)
        ->description(
            "If set, the snapshot downloader will verify snapshots on startup."
            " It will not report founded problems but just re-download broken pieces")
        ->capture_default_str();
    cli.add_option("--torrent.download.rate", snapshot_settings.bittorrent_settings.download_rate_limit)
        ->description("Download rate limit for BitTorrent client in megabytes per seconds")
        ->capture_default_str();
    cli.add_option("--torrent.upload.rate", snapshot_settings.bittorrent_settings.upload_rate_limit)
        ->description("Upload rate limit for BitTorrent client in megabytes per seconds")
        ->capture_default_str();
    cli.add_option("--torrent.download.slots", snapshot_settings.bittorrent_settings.active_downloads)
        ->description(
            "Number of BitTorrent files to download in parallel."
            " If network has enough seeders, then 1-3 slots are enough, otherwise please increase to 5-7"
            " (too big value will slow down everything)")
        ->capture_default_str();
    cli.add_flag("--torrent.warn_on_error_alerts", snapshot_settings.bittorrent_settings.warn_on_error_alerts)
        ->description("Flag indicating if BitTorrent errors must be logged as warnings")
        ->capture_default_str();
}

}  // namespace silkworm::cmd::common
