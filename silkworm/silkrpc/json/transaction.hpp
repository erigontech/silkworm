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
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkworm {

void to_json(nlohmann::json& json, const Transaction& transaction);

}  // namespace silkworm

namespace silkworm::rpc {

struct GlazeJsonTransaction {
    char from[addressSize];
    char gas[int64Size];
    char hash[hashSize];
    std::string input;
    char nonce[int64Size];
    std::optional<std::string> yparity;
    std::optional<std::string> chain_id;
    std::optional<std::string> max_fee_per_gas;
    std::optional<std::string> max_pri_fee_per_gas;
    std::optional<std::vector<GlazeJsonAccessList>> access_list;
    std::optional<std::string> to;
    std::optional<std::monostate> nullto;
    char value[int64Size];
    char type[int64Size];
    char v[hashSize];
    char r[hashSize];
    char s[hashSize];

    char transaction_index[int64Size];
    char block_hash[hashSize];
    char block_number[int64Size];
    char gas_price[int64Size];

    struct glaze {
        using T = GlazeJsonTransaction;

        static constexpr auto value = glz::object(
            "from", &T::from,
            "gas", &T::gas,
            "hash", &T::hash,
            "input", &T::input,
            "nonce", &T::nonce,
            "yParity", &T::yparity,
            "chainId", &T::chain_id,
            "maxPriorityFeePerGas", &T::max_pri_fee_per_gas,
            "maxFeePerGas", &T::max_fee_per_gas,
            "accessList", &T::access_list,
            "to", &T::to,
            "to", &T::nullto,
            "value", &T::value,
            "type", &T::type,
            "v", &T::v,
            "r", &T::r,
            "s", &T::s,
            "transactionIndex", &T::transaction_index,
            "blockHash", &T::block_hash,
            "blockNumber", &T::block_number,
            "gasPrice", &T::gas_price);
    };
};

void make_glaze_json_transaction(const silkworm::Transaction& tx, GlazeJsonTransaction& json_tx);

void to_json(nlohmann::json& json, const Transaction& transaction);

}  // namespace silkworm::rpc
