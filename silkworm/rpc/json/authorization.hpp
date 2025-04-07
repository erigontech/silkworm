// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/json/glaze.hpp>

namespace silkworm::rpc {

struct GlazeJsonAuthorization {
    char chain_id[kInt256HexSize]{};
    char address[kAddressHexSize]{};
    char y_parity[sizeof(uint8_t)]{};
    char r[kInt256HexSize]{};
    char s[kInt256HexSize]{};
    std::vector<std::string> storage_keys;
    struct glaze {
        using T = GlazeJsonAuthorization;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "chainId", &T::chain_id,
            "address", &T::address,
            "yParity", &T::y_parity,
            "r", &T::r,
            "s", &T::s);
    };
};

}  // namespace silkworm::rpc

namespace silkworm {

void from_json(const nlohmann::json& json, Authorization& entry);
void to_json(nlohmann::json& json, const Authorization& authorization);

}  // namespace silkworm
