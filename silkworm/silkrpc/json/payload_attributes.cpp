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

#include <cstring>
#include <utility>

#include <silkworm/core/common/util.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const PayloadAttributes& payload_attributes) {
    json["timestamp"] = to_quantity(payload_attributes.timestamp);
    json["prevRandao"] = payload_attributes.prev_randao;
    json["feeRecipient"] = payload_attributes.suggested_fee_recipient;
}

void from_json(const nlohmann::json& json, PayloadAttributes& payload_attributes) {
    payload_attributes = PayloadAttributes{
        .timestamp = static_cast<uint64_t>(std::stol(json.at("timestamp").get<std::string>(), nullptr, 16)),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .suggested_fee_recipient = json.at("feeRecipient").get<evmc::address>(),
    };
}

}  // namespace silkworm::rpc
