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

#include "call.hpp"

#include <cstring>
#include <utility>

#include <silkworm/core/common/util.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void from_json(const nlohmann::json& json, Call& call) {
    if (json.count("from") != 0) {
        call.from = json.at("from").get<evmc::address>();
    }
    if (json.count("to") != 0) {
        const auto& to = json.at("to");
        if (!to.is_null()) {
            call.to = json.at("to").get<evmc::address>();
        }
    }
    if (json.count("nonce") != 0) {
        const auto& json_nonce = json.at("nonce");
        if (json_nonce.is_string()) {
            call.nonce = std::stol(json_nonce.get<std::string>(), nullptr, 16);
        } else {
            call.nonce = json_nonce.get<uint64_t>();
        }
    }
    if (json.count("gas") != 0) {
        const auto& json_gas = json.at("gas");
        if (json_gas.is_string()) {
            call.gas = std::stol(json_gas.get<std::string>(), nullptr, 16);
        } else {
            call.gas = json_gas.get<uint64_t>();
        }
    }
    if (json.count("gasPrice") != 0) {
        call.gas_price = json.at("gasPrice").get<intx::uint256>();
    }
    if (json.count("value") != 0) {
        call.value = json.at("value").get<intx::uint256>();
    }
    if (json.count("data") != 0) {
        const auto json_data = json.at("data").get<std::string>();
        call.data = silkworm::from_hex(json_data);
    }
    if (json.count("accessList") != 0) {
        call.access_list = json.at("accessList").get<AccessList>();
    }
}

struct GlazeJsonCall {
    char jsonrpc[jsonVersionSize] = "2.0";
    uint32_t id;
    char result[2048];
    struct glaze {
        using T = GlazeJsonCall;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

struct GlazeJsonCallResultAsString {
    char jsonrpc[jsonVersionSize] = "2.0";
    uint32_t id;
    std::string result;
    struct glaze {
        using T = GlazeJsonCallResultAsString;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_content(std::string& reply, uint32_t id, const silkworm::Bytes& call_result) {
    if (call_result.size() * 2 + 2 + 1 > ethCallResultFixedSize) {
        GlazeJsonCallResultAsString log_json_data{};
        log_json_data.result.reserve(call_result.size() * 2 + 2);
        log_json_data.id = id;
        log_json_data.result = "0x" + silkworm::to_hex(call_result);
        glz::write_json(std::move(log_json_data), reply);
    } else {
        GlazeJsonCall log_json_data{};
        log_json_data.id = id;
        to_hex(log_json_data.result, call_result);
        glz::write_json(std::move(log_json_data), reply);
    }
}

void from_json(const nlohmann::json& json, Bundle& call) {
    call.transactions = json.at("transactions").get<std::vector<Call>>();
    if (json.count("blockOverride") != 0) {
        call.block_override = json.at("blockOverride").get<BlockOverride>();
    }
}

void from_json(const nlohmann::json& json, StateContext& state_context) {
    state_context.block_number = json.at("blockNumber").get<BlockNumberOrHash>();

    if (json.count("transactionIndex ") != 0) {
        state_context.transaction_index = json.at("transactionIndex ").get<std::int32_t>();
    }
}

void from_json(const nlohmann::json& json, BlockOverride& block_override) {
    if (json.count("blockNumber") != 0) {
        block_override.block_number = json.at("blockNumber").get<std::uint64_t>();
    }
    if (json.count("coinbase") != 0) {
        block_override.coin_base = json.at("coinbase").get<evmc::address>();
    }
    if (json.count("timestamp") != 0) {
        block_override.timestamp = json.at("timestamp").get<std::uint64_t>();
    }
    if (json.count("difficulty") != 0) {
        block_override.difficulty = json.at("difficulty").get<intx::uint256>();
    }
    if (json.count("gasLimit") != 0) {
        block_override.gas_limit = json.at("gasLimit").get<std::uint64_t>();
    }
    if (json.count("baseFee") != 0) {
        block_override.base_fee = json.at("baseFee").get<std::uint64_t>();
    }
}
}  // namespace silkworm::rpc
