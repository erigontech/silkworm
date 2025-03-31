// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include "history.hpp"

namespace silkworm::datastore::kvdb {

struct Domain {
    const MapConfig& values_table;
    bool has_large_values;
    std::optional<History> history;
};

}  // namespace silkworm::datastore::kvdb
