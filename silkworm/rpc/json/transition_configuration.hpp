// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const TransitionConfiguration& transition_configuration);
void from_json(const nlohmann::json& json, TransitionConfiguration& transition_configuration);

}  // namespace silkworm::rpc
