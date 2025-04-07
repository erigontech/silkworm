// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

namespace silkworm::protocol {

//! \see EthashRuleSet
struct EthashConfig {
    bool validate_seal{true};

    nlohmann::json to_json() const noexcept;

    static std::optional<EthashConfig> from_json(const nlohmann::json& json) noexcept;

    bool operator==(const EthashConfig&) const = default;
};

}  // namespace silkworm::protocol
