// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>

namespace silkworm::datastore::etl {

struct CollectorSettings {
    std::filesystem::path work_path;
    size_t buffer_size{};
};

}  // namespace silkworm::datastore::etl
