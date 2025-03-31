// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

void from_json(const nlohmann::json& json, Log& log);
void to_json(nlohmann::json& json, const Log& log);
void to_json(nlohmann::json& json, const std::vector<Logs>& logs);

void make_glaze_json_content(const nlohmann::json& request_json, const Logs& logs, std::string& json_reply);

}  // namespace silkworm::rpc
