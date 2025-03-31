// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstring>

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/common/util.hpp>

#include "filter.hpp"
#include "types.hpp"
#include "withdrawal.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const ExecutionPayload& execution_payload) {
    nlohmann::json transaction_list;
    for (const auto& transaction : execution_payload.transactions) {
        transaction_list.push_back("0x" + silkworm::to_hex(transaction));
    }
    json["parentHash"] = execution_payload.parent_hash;
    json["feeRecipient"] = execution_payload.suggested_fee_recipient;
    json["stateRoot"] = execution_payload.state_root;
    json["receiptsRoot"] = execution_payload.receipts_root;
    json["logsBloom"] = "0x" + silkworm::to_hex(execution_payload.logs_bloom);
    json["prevRandao"] = execution_payload.prev_randao;
    json["blockNumber"] = to_quantity(execution_payload.block_num);
    json["gasLimit"] = to_quantity(execution_payload.gas_limit);
    json["gasUsed"] = to_quantity(execution_payload.gas_used);
    json["timestamp"] = to_quantity(execution_payload.timestamp);
    json["extraData"] = "0x" + silkworm::to_hex(execution_payload.extra_data);
    json["baseFeePerGas"] = to_quantity(execution_payload.base_fee);
    json["blockHash"] = execution_payload.block_hash;
    json["transactions"] = transaction_list;
    if (execution_payload.withdrawals) {
        json["withdrawals"] = execution_payload.withdrawals.value();
    }
    if (execution_payload.blob_gas_used) {
        json["blobGasUsed"] = to_quantity(*execution_payload.blob_gas_used);
    }
    if (execution_payload.excess_blob_gas) {
        json["excessBlobGas"] = to_quantity(*execution_payload.excess_blob_gas);
    }
}

void from_json(const nlohmann::json& json, ExecutionPayload& execution_payload) {
    // Parse logs bloom
    silkworm::Bloom logs_bloom;
    std::memcpy(&logs_bloom[0],
                silkworm::from_hex(json.at("logsBloom").get<std::string>())->data(),
                silkworm::kBloomByteLength);
    // Parse transactions
    std::vector<Bytes> transactions;
    for (const auto& hex_transaction : json.at("transactions")) {
        const auto hex_bytes{from_hex(hex_transaction.get<std::string>())};
        if (hex_bytes) {
            transactions.push_back(*hex_bytes);
        } else {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument),
                                    "ExecutionPayload: invalid hex transaction: " + hex_transaction.dump()};
        }
    }
    // Optionally parse V2 fields
    std::optional<std::vector<Withdrawal>> withdrawals;
    if (json.contains("withdrawals")) {
        withdrawals = json.at("withdrawals").get<std::vector<Withdrawal>>();
    }

    // Optional parse V3 fields
    std::optional<uint64_t> blob_gas_used;
    if (json.contains("blobGasUsed")) {
        blob_gas_used = from_quantity(json.at("blobGasUsed").get<std::string>());
    }
    std::optional<uint64_t> excess_blob_gas;
    if (json.contains("excessBlobGas")) {
        excess_blob_gas = from_quantity(json.at("excessBlobGas").get<std::string>());
    }

    execution_payload = ExecutionPayload{
        .block_num = from_quantity(json.at("blockNumber").get<std::string>()),
        .timestamp = from_quantity(json.at("timestamp").get<std::string>()),
        .gas_limit = from_quantity(json.at("gasLimit").get<std::string>()),
        .gas_used = from_quantity(json.at("gasUsed").get<std::string>()),
        .suggested_fee_recipient = json.at("feeRecipient").get<evmc::address>(),
        .state_root = json.at("stateRoot").get<evmc::bytes32>(),
        .receipts_root = json.at("receiptsRoot").get<evmc::bytes32>(),
        .parent_hash = json.at("parentHash").get<evmc::bytes32>(),
        .block_hash = json.at("blockHash").get<evmc::bytes32>(),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .base_fee = json.at("baseFeePerGas").get<intx::uint256>(),
        .logs_bloom = logs_bloom,
        .extra_data = *silkworm::from_hex(json.at("extraData").get<std::string>()),
        .transactions = transactions,
        .withdrawals = std::move(withdrawals),
        .blob_gas_used = blob_gas_used,
        .excess_blob_gas = excess_blob_gas,
    };

    // Set the ExecutionPayload version (default is V1)
    SILKWORM_ASSERT(execution_payload.version == ExecutionPayload::kV1);
    if (execution_payload.withdrawals) {
        if (execution_payload.blob_gas_used.has_value() != execution_payload.excess_blob_gas.has_value()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument),
                                    "ExecutionPayload: invalid V3 payload, missing " +
                                        std::string{execution_payload.blob_gas_used ? "excess_blob_gas" : "blob_gas_used"}};
        }

        if (execution_payload.blob_gas_used && execution_payload.excess_blob_gas) {
            execution_payload.version = ExecutionPayload::kV3;
        } else {
            execution_payload.version = ExecutionPayload::kV2;
        }
    } else {
        if (execution_payload.blob_gas_used || execution_payload.excess_blob_gas) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument),
                                    "ExecutionPayload: invalid V3 payload, missing withdrawals"};
        }
    }
}

void to_json(nlohmann::json& json, const ExecutionPayloadAndValue& reply) {
    json["executionPayload"] = reply.payload;
    json["blockValue"] = to_quantity(reply.block_value);
}

void to_json(nlohmann::json& json, const ExecutionPayloadBody& body) {
    if (!body.transactions) {
        json = nlohmann::json::value_t::null;
        return;
    }

    nlohmann::json transaction_list;
    for (const auto& transaction : *body.transactions) {
        transaction_list.push_back("0x" + silkworm::to_hex(transaction));
    }
    json["transactions"] = transaction_list;
    if (body.withdrawals) {
        json["withdrawals"] = body.withdrawals.value();
    } else {
        json["withdrawals"] = nlohmann::json::value_t::null;
    }
}

}  // namespace silkworm::rpc
