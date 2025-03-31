// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <vector>

namespace silkworm {

void move_file(const std::filesystem::path& path, const std::filesystem::path& target_dir_path);
void move_files(const std::vector<std::filesystem::path>& paths, const std::filesystem::path& target_dir_path);

}  // namespace silkworm
