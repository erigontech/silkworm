// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/call_bundle.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const struct CallBundleTxInfo& tx_info);

void to_json(nlohmann::json& json, const struct CallBundleInfo& bundle_info);

}  // namespace silkworm::rpc
