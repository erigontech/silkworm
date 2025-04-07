// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/node_info.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const NodeInfoPorts& node_info_ports);
void to_json(nlohmann::json& json, const NodeInfo& node_info);

}  // namespace silkworm::rpc
