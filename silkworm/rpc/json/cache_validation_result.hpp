// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include "../types/cache_validation_result.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const CacheValidationResult& result);

}  // namespace silkworm::rpc
