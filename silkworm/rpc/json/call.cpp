// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "call.hpp"

#include <utility>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>

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
    if (json.count("maxFeePerGas") != 0) {
        call.max_fee_per_gas = json.at("maxFeePerGas").get<intx::uint256>();
    }
    if (json.count("maxPriorityFeePerGas") != 0) {
        call.max_priority_fee_per_gas = json.at("maxPriorityFeePerGas").get<intx::uint256>();
    }
    if (json.count("value") != 0) {
        call.value = json.at("value").get<intx::uint256>();
    }

    // backward compatibility: both `data` and `input` fields are accepted as input
    if (json.count("data") != 0) {
        const auto json_data = json.at("data").get<std::string>();
        call.data = silkworm::from_hex(json_data);
    }
    if (json.count("input") != 0) {
        const auto json_data = json.at("input").get<std::string>();
        call.data = silkworm::from_hex(json_data);
    }

    if (json.count("accessList") != 0) {
        call.access_list = json.at("accessList").get<AccessList>();
    }
}

struct GlazeJsonCall {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    char result[2048];
    struct glaze {
        using T = GlazeJsonCall;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

struct GlazeJsonCallResultAsString {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    std::string result;
    struct glaze {
        using T = GlazeJsonCallResultAsString;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_content(const nlohmann::json& request_json, const silkworm::Bytes& call_result, std::string& json_reply) {
    if (call_result.size() * 2 + 2 + 1 > kEthCallResultFixedSize) {
        GlazeJsonCallResultAsString log_json_data{};

        log_json_data.result.reserve(call_result.size() * 2 + 2);
        log_json_data.id = make_jsonrpc_id(request_json);
        log_json_data.result = "0x" + silkworm::to_hex(call_result);

        glz::write_json(std::move(log_json_data), json_reply);
    } else {
        GlazeJsonCall log_json_data{};

        log_json_data.id = make_jsonrpc_id(request_json);
        to_hex(log_json_data.result, call_result);

        glz::write_json(std::move(log_json_data), json_reply);
    }
}

void from_json(const nlohmann::json& json, Bundle& call) {
    call.transactions = json.at("transactions").get<std::vector<Call>>();
    if (json.contains("blockOverride")) {
        call.block_override = json["blockOverride"].get<BlockOverrides>();
    }
}

void from_json(const nlohmann::json& json, SimulationContext& sc) {
    sc.block_num = json["blockNumber"].get<BlockNumOrHash>();

    if (json.contains("transactionIndex")) {
        sc.transaction_index = json["transactionIndex"].get<std::int32_t>();
    }
}

void from_json(const nlohmann::json& json, AccountOverrides& ao) {
    if (json.contains("balance")) {
        ao.balance = json["balance"].get<intx::uint256>();
    }
    if (json.count("nonce") != 0) {
        const auto& json_nonce = json.at("nonce");
        if (json_nonce.is_string()) {
            ao.nonce = std::stol(json_nonce.get<std::string>(), nullptr, 16);
        } else {
            ao.nonce = json_nonce.get<uint64_t>();
        }
    }
    if (json.contains("code")) {
        const auto json_data = json.at("code").get<std::string>();
        ao.code = silkworm::from_hex(json_data);
        ao.code_hash = std::bit_cast<evmc_bytes32>(keccak256(ao.code.value()));
    }
    if (json.contains("state")) {
        const auto& state = json["state"];
        auto ss = state.get<std::map<std::string, std::string>>();
        for (const auto& entry : ss) {
            auto b32 = bytes32_from_hex(entry.first);
            auto u256 = intx::from_string<intx::uint256>(entry.second);

            ao.state.emplace(b32, u256);
        }
    }
    if (json.contains("stateDiff")) {
        const auto& state = json["stateDiff"];
        auto ss = state.get<std::map<std::string, std::string>>();
        for (const auto& entry : ss) {
            auto b32 = bytes32_from_hex(entry.first);
            auto u256 = intx::from_string<intx::uint256>(entry.second);

            ao.state_diff.emplace(b32, u256);
        }
    }
}

void from_json(const nlohmann::json& json, BlockOverrides& bo) {
    if (json.contains("blockNumber")) {
        const auto& block_num_json = json["blockNumber"];
        if (block_num_json.is_string()) {
            bo.block_num = std::stoull(block_num_json.get<std::string>(), nullptr, /*base=*/16);
        } else {
            bo.block_num = block_num_json.get<BlockNum>();
        }
    }
    if (json.contains("coinbase")) {
        bo.coin_base = json["coinbase"].get<evmc::address>();
    }
    if (json.contains("timestamp")) {
        bo.timestamp = json["timestamp"].get<std::uint64_t>();
    }
    if (json.contains("difficulty")) {
        bo.difficulty = json["difficulty"].get<intx::uint256>();
    }
    if (json.contains("gasLimit")) {
        const auto& gas_limit_json = json["gasLimit"];
        if (gas_limit_json.is_string()) {
            bo.gas_limit = std::stoull(gas_limit_json.get<std::string>(), nullptr, /*base=*/16);
        } else {
            bo.gas_limit = gas_limit_json.get<uint64_t>();
        }
    }
    if (json.contains("baseFee")) {
        const auto& base_fee_json = json["baseFee"];
        if (base_fee_json.is_string()) {
            bo.base_fee = std::stoull(base_fee_json.get<std::string>(), nullptr, /*base=*/16);
        } else {
            bo.base_fee = base_fee_json.get<uint64_t>();
        }
    }
}

void from_json(const nlohmann::json& json, AccountsOverrides& accounts_overrides) {
    for (const auto& el : json.items()) {
        const auto key = hex_to_address(el.key(), /*return_zero_on_err=*/true);
        const auto value = el.value().get<AccountOverrides>();

        accounts_overrides.emplace(key, value);
    }
}
}  // namespace silkworm::rpc
