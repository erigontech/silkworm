// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "kvdb/schema.hpp"
#include "snapshots/schema.hpp"

namespace silkworm::datastore {

struct Schema {
    kvdb::Schema kvdb;
    snapshots::Schema snapshots;
};

}  // namespace silkworm::datastore
