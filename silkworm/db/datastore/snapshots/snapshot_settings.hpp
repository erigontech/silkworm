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

#include <silkworm/infra/common/directories.hpp>

#include "bittorrent/settings.hpp"

namespace silkworm::snapshots {

struct SnapshotSettings {
    std::filesystem::path repository_path{DataDirectory{}.snapshots().path()};
    bool enabled{true};
    bool no_downloader{false};
    bittorrent::BitTorrentSettings bittorrent_settings;
    // Keep collated data in mdbx
    bool keep_blocks{false};
    // Stop producing new snapshots
    bool stop_freezer{false};
    bool verify_on_startup{false};
    bool no_seeding{false};
};

}  // namespace silkworm::snapshots
