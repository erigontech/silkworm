// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "access_list_entry.hpp"

#include <silkworm/core/common/util.hpp>

#include "types.hpp"

namespace silkworm {

void from_json(const nlohmann::json& json, AccessListEntry& entry) {
    entry.account = json.at("address").get<evmc::address>();
    entry.storage_keys = json.at("storageKeys").get<std::vector<evmc::bytes32>>();
}

void to_json(nlohmann::json& json, const AccessListEntry& access_list) {
    json["address"] = access_list.account;
    json["storageKeys"] = access_list.storage_keys;
}

}  // namespace silkworm
