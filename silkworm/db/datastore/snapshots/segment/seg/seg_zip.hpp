// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

namespace silkworm::snapshots::seg {

void seg_zip(const std::filesystem::path& path);
void seg_unzip(const std::filesystem::path& path);

}  // namespace silkworm::snapshots::seg
