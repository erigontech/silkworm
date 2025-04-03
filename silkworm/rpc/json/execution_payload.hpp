// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const ExecutionPayload& execution_payload);
void from_json(const nlohmann::json& json, ExecutionPayload& execution_payload);

void to_json(nlohmann::json& json, const ExecutionPayloadAndValue& reply);

void to_json(nlohmann::json& json, const ExecutionPayloadBody& body);

}  // namespace silkworm::rpc
