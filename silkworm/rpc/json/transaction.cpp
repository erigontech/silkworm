// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "transaction.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/json/types.hpp>

namespace silkworm {

void to_json(nlohmann::json& json, const Transaction& transaction) {
    if (const std::optional<evmc::address> sender{transaction.sender()}; sender) {
        json["from"] = *sender;
    }
    json["gas"] = rpc::to_quantity(transaction.gas_limit);
    json["hash"] = transaction.hash();
    json["input"] = "0x" + silkworm::to_hex(transaction.data);
    json["nonce"] = rpc::to_quantity(transaction.nonce);
    if (transaction.to) {
        json["to"] = transaction.to.value();
    } else {
        json["to"] = nullptr;
    }
    json["type"] = rpc::to_quantity(static_cast<uint64_t>(transaction.type));

    if (transaction.type == silkworm::TransactionType::kDynamicFee ||
        transaction.type == silkworm::TransactionType::kBlob ||
        transaction.type == silkworm::TransactionType::kSetCode) {
        json["maxPriorityFeePerGas"] = rpc::to_quantity(transaction.max_priority_fee_per_gas);
        json["maxFeePerGas"] = rpc::to_quantity(transaction.max_fee_per_gas);
    }
    if (transaction.type != silkworm::TransactionType::kLegacy) {
        json["chainId"] = rpc::to_quantity(*transaction.chain_id);
        json["v"] = rpc::to_quantity(uint64_t{transaction.odd_y_parity});
        json["accessList"] = transaction.access_list;  // EIP2930
        json["yParity"] = rpc::to_quantity(transaction.odd_y_parity);
    } else if (transaction.chain_id) {
        json["chainId"] = rpc::to_quantity(*transaction.chain_id);
        json["v"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    } else {
        json["v"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    }
    if (transaction.type == TransactionType::kSetCode) {
        json["authorizations"] = transaction.authorizations;  // EIP7702
    }

    json["value"] = rpc::to_quantity(transaction.value);
    json["r"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.r));
    json["s"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.s));
}

}  // namespace silkworm

namespace silkworm::rpc {

void make_glaze_json_transaction(const silkworm::Transaction& tx, GlazeJsonTransaction& json_tx) {
    if (const std::optional<evmc::address> sender{tx.sender()}; sender) {
        to_hex(std::span(json_tx.from), sender->bytes);
    }

    if (tx.to) {
        json_tx.to = std::make_optional("0x" + silkworm::to_hex(tx.to.value().bytes));
    } else {
        std::monostate null_value{};
        json_tx.nullto = std::make_optional(null_value);
    }
    to_quantity(std::span(json_tx.gas), tx.gas_limit);
    to_hex(std::span(json_tx.hash), tx.hash().bytes);
    json_tx.input.reserve(tx.data.size() * 2 + 3);
    json_tx.input = "0x" + silkworm::to_hex(tx.data);
    to_quantity(std::span(json_tx.nonce), tx.nonce);
    to_quantity(std::span(json_tx.type), static_cast<uint64_t>(tx.type));

    if (tx.type != silkworm::TransactionType::kLegacy) {
        json_tx.chain_id = std::make_optional(to_quantity(*tx.chain_id));
        to_quantity(std::span(json_tx.v), uint64_t{tx.odd_y_parity});

        std::vector<GlazeJsonAccessList> glaze_access_list;
        glaze_access_list.reserve(tx.access_list.size());
        for (const auto& access_list : tx.access_list) {
            GlazeJsonAccessList access_list_json_tx;
            to_hex(std::span(access_list_json_tx.address), access_list.account.bytes);
            for (const auto& storage_key : access_list.storage_keys) {
                auto key_hash = silkworm::to_bytes32({storage_key.bytes, silkworm::kHashLength});
                access_list_json_tx.storage_keys.push_back("0x" + silkworm::to_hex(key_hash.bytes));
            }
            glaze_access_list.push_back(std::move(access_list_json_tx));
        }
        json_tx.access_list = std::make_optional(std::move(glaze_access_list));
        json_tx.yparity = std::make_optional(rpc::to_quantity(tx.odd_y_parity));
    } else if (tx.chain_id) {
        json_tx.chain_id = std::make_optional(to_quantity(*tx.chain_id));
        to_quantity(std::span(json_tx.v), silkworm::endian::to_big_compact(tx.v()));
    } else {
        rpc::to_quantity(std::span(json_tx.v), silkworm::endian::to_big_compact(tx.v()));
    }
    if (tx.type == silkworm::TransactionType::kDynamicFee ||
        tx.type == silkworm::TransactionType::kBlob ||
        tx.type == silkworm::TransactionType::kSetCode) {
        json_tx.max_pri_fee_per_gas = std::make_optional(rpc::to_quantity(tx.max_priority_fee_per_gas));
        json_tx.max_fee_per_gas = std::make_optional(rpc::to_quantity(tx.max_fee_per_gas));
    }
    if (tx.type == silkworm::TransactionType::kBlob) {
        json_tx.max_fee_per_blob_gas = std::make_optional(rpc::to_quantity(tx.max_fee_per_blob_gas));
        std::vector<std::string> hashes;
        for (const auto& curr_hash : tx.blob_versioned_hashes) {
            auto hash = silkworm::to_hex(curr_hash.bytes, /* with_prefix = */ true);
            hashes.push_back(hash);
        }
        json_tx.blob_versioned_hashes = std::make_optional(hashes);
    }
    if (tx.type == silkworm::TransactionType::kSetCode) {
        std::vector<GlazeJsonAuthorization> glaze_authorizations;
        glaze_authorizations.reserve(tx.authorizations.size());
        for (const auto& authorization : tx.authorizations) {
            GlazeJsonAuthorization authorization_json_tx;
            to_quantity(std::span(authorization_json_tx.chain_id), silkworm::endian::to_big_compact(authorization.chain_id));
            to_hex(std::span(authorization_json_tx.address), authorization.address.bytes);
            to_quantity(std::span(authorization_json_tx.y_parity), silkworm::endian::to_big_compact(authorization.y_parity));
            to_quantity(std::span(authorization_json_tx.r), silkworm::endian::to_big_compact(authorization.r));
            to_quantity(std::span(authorization_json_tx.s), silkworm::endian::to_big_compact(authorization.s));

            glaze_authorizations.push_back(std::move(authorization_json_tx));
        }
        json_tx.authorizations = std::make_optional(std::move(glaze_authorizations));
    }
    to_quantity(std::span(json_tx.value), tx.value);
    to_quantity(std::span(json_tx.r), silkworm::endian::to_big_compact(tx.r));
    to_quantity(std::span(json_tx.s), silkworm::endian::to_big_compact(tx.s));
}

struct GlazeJsonTransactionReply {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    GlazeJsonTransaction result;

    struct glaze {
        using T = GlazeJsonTransactionReply;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_content(const nlohmann::json& request_json, const Transaction& tx, std::string& json_reply) {
    GlazeJsonTransactionReply tx_json_data{};
    tx_json_data.id = make_jsonrpc_id(request_json);
    to_quantity(std::span(tx_json_data.result.transaction_index), tx.transaction_index);
    to_quantity(std::span(tx_json_data.result.block_num), tx.block_num);
    to_hex(std::span(tx_json_data.result.block_hash), tx.block_hash.bytes);
    to_quantity(std::span(tx_json_data.result.gas_price), tx.effective_gas_price());
    make_glaze_json_transaction(tx, tx_json_data.result);

    glz::write_json(tx_json_data, json_reply);
}

void to_json(nlohmann::json& json, const Transaction& transaction) {
    to_json(json, static_cast<const silkworm::Transaction&>(transaction));

    json["gasPrice"] = to_quantity(transaction.effective_gas_price());
    if (transaction.queued_in_pool) {
        json["blockHash"] = nullptr;
        json["blockNumber"] = nullptr;
        json["transactionIndex"] = nullptr;
    } else {
        json["blockHash"] = transaction.block_hash;
        json["blockNumber"] = to_quantity(transaction.block_num);
        json["transactionIndex"] = to_quantity(transaction.transaction_index);
    }
}

}  // namespace silkworm::rpc
