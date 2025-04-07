// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "filesystem.hpp"

namespace silkworm {

void move_file(const std::filesystem::path& path, const std::filesystem::path& target_dir_path) {
    std::filesystem::rename(path, target_dir_path / path.filename());
}

void move_files(const std::vector<std::filesystem::path>& paths, const std::filesystem::path& target_dir_path) {
    for (const std::filesystem::path& path : paths) {
        move_file(path, target_dir_path);
    }
}

}  // namespace silkworm
