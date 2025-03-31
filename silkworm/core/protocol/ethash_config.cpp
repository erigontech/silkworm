// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ethash_config.hpp"

namespace silkworm::protocol {

nlohmann::json EthashConfig::to_json() const noexcept {
    nlohmann::json ret(nlohmann::json::value_t::object);
    if (!validate_seal) {
        ret.emplace("validateSeal", validate_seal);
    }
    return ret;
}

std::optional<EthashConfig> EthashConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    EthashConfig config;
    if (json.contains("validateSeal")) {
        config.validate_seal = json["validateSeal"].get<bool>();
    }
    return config;
}

}  // namespace silkworm::protocol
