// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "parse_path.hpp"

#include <cstring>

namespace silkworm::capi {

std::filesystem::path parse_path(const char data_dir_path[SILKWORM_PATH_SIZE]) {
    // Treat as char8_t so that filesystem::path assumes UTF-8 encoding of the input path
    auto begin = reinterpret_cast<const char8_t*>(data_dir_path);
    size_t len = strnlen(data_dir_path, SILKWORM_PATH_SIZE);
    return std::filesystem::path{begin, begin + len};
}

}  // namespace silkworm::capi
