// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/call.hpp>

namespace silkworm::rpc {

void from_json(const nlohmann::json&, Call&);
void from_json(const nlohmann::json&, Bundle&);
void from_json(const nlohmann::json&, SimulationContext&);
void from_json(const nlohmann::json&, AccountOverrides&);
void from_json(const nlohmann::json&, BlockOverrides&);
void from_json(const nlohmann::json&, AccountsOverrides&);

void make_glaze_json_content(const nlohmann::json& request_json, const silkworm::Bytes& call_result, std::string& json_reply);

}  // namespace silkworm::rpc
