// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "inverted_index.hpp"

namespace silkworm::datastore::kvdb {

struct History {
    const MapConfig& values_table;
    bool has_large_values;
    InvertedIndex inverted_index;
};

}  // namespace silkworm::datastore::kvdb
