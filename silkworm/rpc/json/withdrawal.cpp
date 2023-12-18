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

namespace silkworm::rpc {

std::optional<std::vector<GlazeJsonWithdrawals>> make_glaze_json_withdrawals(const BlockBody& block) {
    std::vector<GlazeJsonWithdrawals> withdrawals;
    withdrawals.reserve(block.withdrawals->size());
    for (std::size_t i{0}; i < block.withdrawals->size(); i++) {
        GlazeJsonWithdrawals item;
        to_quantity(std::span(item.index), (*(block.withdrawals))[i].index);
        to_quantity(std::span(item.amount), (*(block.withdrawals))[i].amount);
        to_quantity(std::span(item.validator_index), (*(block.withdrawals))[i].validator_index);
        to_hex(std::span(item.address), (*(block.withdrawals))[i].address.bytes);
        withdrawals.push_back(item);
    }
    return make_optional(std::move(withdrawals));
}

}  // namespace silkworm::rpc
