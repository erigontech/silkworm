// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/rpc/json/glaze.hpp>

namespace silkworm::rpc {
struct GlazeJsonAccessList {
    char address[kAddressHexSize]{};
    std::vector<std::string> storage_keys;
    struct glaze {
        using T = GlazeJsonAccessList;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "address", &T::address,
            "storageKeys", &T::storage_keys);
    };
};

}  // namespace silkworm::rpc

namespace silkworm {

void from_json(const nlohmann::json& json, AccessListEntry& entry);
void to_json(nlohmann::json& json, const AccessListEntry& access_list);

}  // namespace silkworm
