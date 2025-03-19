/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
