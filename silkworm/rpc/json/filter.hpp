// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/filter.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Filter& filter);
void from_json(const nlohmann::json& json, Filter& filter);

void from_json(const nlohmann::json& json, LogFilterOptions& filter_options);

}  // namespace silkworm::rpc
