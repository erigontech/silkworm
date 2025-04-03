// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

namespace silkworm::datastore::kvdb {

struct MapConfig;

struct InvertedIndex {
    const MapConfig& keys_table;
    const MapConfig& index_table;
};

}  // namespace silkworm::datastore::kvdb
