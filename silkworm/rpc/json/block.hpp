// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Block& b);

void make_glaze_json_content(const nlohmann::json& request_json, const Block& b, std::string& json_reply);
void make_glaze_json_null_content(const nlohmann::json& request_json, std::string& json_reply);

}  // namespace silkworm::rpc
