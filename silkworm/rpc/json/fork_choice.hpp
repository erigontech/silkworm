// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/execution_payload.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const ForkChoiceState& forkchoice_state);
void from_json(const nlohmann::json& json, ForkChoiceState& forkchoice_state);

void to_json(nlohmann::json& json, const ForkChoiceUpdatedReply& forkchoice_updated_reply);

}  // namespace silkworm::rpc
