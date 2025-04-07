// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "trackers.hpp"

namespace silkworm::snapshots::bittorrent {

const std::vector<std::string> kBestTrackers{
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://opentracker.i2p.rocks:6969/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://open.stealth.si:80/announce",
};

}  // namespace silkworm::snapshots::bittorrent
