// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <map>
#include <memory>
#include <optional>

#include <silkworm/core/common/bytes.hpp>

#include "../common/entity_name.hpp"
#include "../common/step.hpp"
#include "common/cache.hpp"

namespace silkworm::snapshots {

struct DomainGetLatestCacheData {
    BytesOrByteView value;
    std::optional<datastore::Step> range_end{0};
};
using DomainGetLatestCache = Cache<DomainGetLatestCacheData>;
using DomainGetLatestCaches = std::map<datastore::EntityName, std::unique_ptr<DomainGetLatestCache>>;

}  // namespace silkworm::snapshots
