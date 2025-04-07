// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/infra/common/application_info.hpp>

namespace silkworm::rpc {

void make_glaze_json_content(const nlohmann::json& request_json, const ApplicationInfo& build_info, std::string& json_reply);

}  // namespace silkworm::rpc
