// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "authorization.hpp"

#include "types.hpp"

namespace silkworm {

void from_json(const nlohmann::json& json, Authorization& entry) {
    entry.chain_id = json.at("chainId").get<intx::uint256>();
    entry.address = json.at("address").get<evmc::address>();
    entry.y_parity = json.at("yParity").get<uint8_t>();
    entry.r = json.at("r").get<intx::uint256>();
    entry.s = json.at("s").get<intx::uint256>();
}

void to_json(nlohmann::json& json, const Authorization& authorization) {
    json["chainId"] = rpc::to_quantity(authorization.chain_id);
    json["address"] = authorization.address;
    json["yParity"] = rpc::to_quantity(authorization.y_parity);
    json["r"] = rpc::to_quantity(authorization.r);
    json["s"] = rpc::to_quantity(authorization.s);
}

}  // namespace silkworm
