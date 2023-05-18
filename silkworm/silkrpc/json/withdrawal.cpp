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

#include "withdrawal.hpp"

#include "types.hpp"

namespace silkworm {

void to_json(nlohmann::json& json, const Withdrawal& withdrawal) {
    json["index"] = rpc::to_quantity(withdrawal.index);
    json["validatorIndex"] = rpc::to_quantity(withdrawal.validator_index);
    json["address"] = withdrawal.address;
    json["amount"] = rpc::to_quantity(withdrawal.amount);
}

void from_json(const nlohmann::json& json, Withdrawal& withdrawal) {
    withdrawal.index = rpc::from_quantity(json.at("index"));
    withdrawal.validator_index = rpc::from_quantity(json.at("validatorIndex"));
    withdrawal.address = json.at("address").get<evmc::address>();
    withdrawal.amount = rpc::from_quantity(json.at("amount"));
}

}  // namespace silkworm
