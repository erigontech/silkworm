// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
