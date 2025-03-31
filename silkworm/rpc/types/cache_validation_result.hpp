// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

#include <silkworm/db/kv/api/state_cache.hpp>

namespace silkworm::rpc {

struct CacheValidationResult {
    const db::kv::api::StateCache::ValidationResult& ref;
};

}  // namespace silkworm::rpc
