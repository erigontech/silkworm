/*
   Copyright 2023 The Silkworm Authors

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

#include "payload_attributes.hpp"

#include <string>
#include <utility>

#include <silkworm/core/types/address.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const PayloadAttributes& payload_attributes) {
    json["timestamp"] = to_quantity(payload_attributes.timestamp);
    json["prevRandao"] = payload_attributes.prev_randao;
    json["suggestedFeeRecipient"] = payload_attributes.suggested_fee_recipient;
}

void from_json(const nlohmann::json& json, PayloadAttributes& payload_attributes) {
    // Optionally parse V2 fields
    std::optional<std::vector<Withdrawal>> withdrawals;
    if (json.contains("withdrawals")) {
        withdrawals = json.at("withdrawals").get<std::vector<Withdrawal>>();
    }

    // Optionally parse V3 fields
    std::optional<evmc::bytes32> parent_beacon_block_root;
    if (json.contains("parentBeaconBlockRoot")) {
        parent_beacon_block_root = json.at("parentBeaconBlockRoot").get<evmc::bytes32>();
    }

    payload_attributes = PayloadAttributes{
        .timestamp = from_quantity(json.at("timestamp").get<std::string>()),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .suggested_fee_recipient = json.at("suggestedFeeRecipient").get<evmc::address>(),
        .withdrawals = std::move(withdrawals),
        .parent_beacon_block_root = parent_beacon_block_root,
    };

    // Set the PayloadAttributes version (default is V1)
    SILKWORM_ASSERT(payload_attributes.version == PayloadAttributes::V1);
    if (payload_attributes.withdrawals) {
        if (payload_attributes.parent_beacon_block_root) {
            payload_attributes.version = PayloadAttributes::V3;
        } else {
            payload_attributes.version = PayloadAttributes::V2;
        }
    }
}

}  // namespace silkworm::rpc
