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

#pragma once

#include <filesystem>

#include <silkworm/db/snapshots/bittorrent/settings.hpp>
#include <silkworm/infra/common/directories.hpp>

namespace silkworm::snapshots {

struct SnapshotSettings {
    std::filesystem::path repository_dir{DataDirectory{}.snapshots().path()};  // Path to the snapshot repository on disk
    bool enabled{true};                                                        // Flag indicating if snapshots are enabled
    bool no_downloader{false};                                                 // Flag indicating if snapshots download is disabled
    bittorrent::BitTorrentSettings bittorrent_settings;                        // The Bittorrent protocol settings
    bool keep_blocks{false};                                                   // Flag indicating if exported blocks should be kept in mdbx
    bool stop_freezer{false};                                                  // Stop producing new snapshots
};

}  // namespace silkworm::snapshots
