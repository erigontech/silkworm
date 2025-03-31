// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string_view>

namespace silkworm::snapshots {

struct Entry {
    std::string_view file_name;
    std::string_view torrent_hash;
};

}  // namespace silkworm::snapshots
