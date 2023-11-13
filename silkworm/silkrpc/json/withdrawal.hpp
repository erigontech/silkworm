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

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/core/types/withdrawal.hpp>
#include <silkworm/silkrpc/json/glaze.hpp>
#include <silkworm/silkrpc/types/block.hpp>

namespace silkworm::rpc {

struct GlazeJsonWithdrawals {
    char index[int64Size];
    char validator_index[int64Size];
    char address[addressSize];
    char amount[int64Size];

    struct glaze {
        using T = GlazeJsonWithdrawals;
        static constexpr auto value = glz::object(
            "index", &T::index,
            "validatorIndex", &T::validator_index,
            "address", &T::address,
            "amount", &T::amount);
    };
};

std::optional<std::vector<GlazeJsonWithdrawals>> make_glaze_json_withdrawals(const BlockBody& block);

}  // namespace silkworm::rpc

namespace silkworm {

void to_json(nlohmann::json& json, const Withdrawal& withdrawal);
void from_json(const nlohmann::json& json, Withdrawal& receipt);

}  // namespace silkworm
