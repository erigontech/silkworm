// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const std::shared_ptr<Receipt> receipt);
void to_json(nlohmann::json& json, const Receipt& receipt);
void from_json(const nlohmann::json& json, std::shared_ptr<Receipt>& receipt);

}  // namespace silkworm::rpc
