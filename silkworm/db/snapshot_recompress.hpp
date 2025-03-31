// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

namespace silkworm::snapshots {

void snapshot_file_recompress(const std::filesystem::path& path);

}
