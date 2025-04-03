// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <utility>

#include <silkworm/db/datastore/common/timestamp.hpp>

#include "../common/entity_name.hpp"
#include "common/cache.hpp"

namespace silkworm::snapshots {

struct InvertedIndexSeekCacheData {
    datastore::Timestamp requested;
    datastore::Timestamp found;
};
using InvertedIndexSeekCache = Cache<InvertedIndexSeekCacheData>;
using InvertedIndexSeekCaches = std::map<datastore::EntityName, std::unique_ptr<InvertedIndexSeekCache>>;

}  // namespace silkworm::snapshots
