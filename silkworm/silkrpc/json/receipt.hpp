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

#include <silkworm/silkrpc/json/glaze.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Receipt& receipt);
void from_json(const nlohmann::json& json, Receipt& receipt);

struct GlazeJsonReceipt {
    char block_hash[kHashHexSize];
    char block_number[kInt64HexSize];
    std::optional<std::string> contract_address;
    std::optional<std::monostate> nullcontract_address;
    char from[kAddressHexSize];
    std::optional<std::string> to;
    std::optional<std::monostate> nullto;
    char cumulative_gas_used[kInt64HexSize];
    char effective_gas_price[kInt64HexSize];
    char gas_used[kInt64HexSize];
    std::optional<std::string> logs;
    std::optional<std::string> logsBloom;
    char status[kInt64HexSize];
    char transaction_hash[kHashHexSize];
    char transaction_index[kInt64HexSize];
    char type[kHashHexSize];

    struct glaze {
        using T = GlazeJsonReceipt;
        static constexpr auto value = glz::object(
            "blockHash", &T::block_hash,
            "blockNumber", &T::block_number,
            "contractAddress", &T::contract_address,
            "contractAddress", &T::nullcontract_address,
            "from", &T::from,
            "to", &T::to,
            "to", &T::nullto,
            "cumulativeGasUsed", &T::cumulative_gas_used,
            "effectiveGasPrice", &T::effective_gas_price,
            "gasUsed", &T::gas_used,
            "logs", &T::logs,
            "logsBloom", &T::logsBloom,
            "status", &T::status,
            "transactionHash", &T::transaction_hash,
            "transactionIndex", &T::transaction_index,
            "type", &T::type
        );
    };
};

void make_glaze_json_receipt(const Receipt& receipt, GlazeJsonReceipt& json_receipt);

}  // namespace silkworm::rpc
