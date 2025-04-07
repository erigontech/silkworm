// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <nlohmann/json.hpp>

#include <silkworm/rpc/json/access_list_entry.hpp>
#include <silkworm/rpc/json/authorization.hpp>
#include <silkworm/rpc/json/glaze.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm {

void to_json(nlohmann::json& json, const Transaction& transaction);

}  // namespace silkworm

namespace silkworm::rpc {

struct GlazeJsonTransaction {
    char from[kAddressHexSize];
    char gas[kInt64HexSize];
    char hash[kHashHexSize];
    char nonce[kInt64HexSize];
    char value[kInt256HexSize];
    char type[kInt64HexSize];
    char v[kInt256HexSize];
    char r[kInt256HexSize];
    char s[kInt256HexSize];
    char transaction_index[kInt64HexSize];
    char block_hash[kHashHexSize];
    char block_num[kInt64HexSize];
    char gas_price[kInt64HexSize];

    std::string input;

    std::optional<std::string> yparity;
    std::optional<std::string> chain_id;
    std::optional<std::string> max_fee_per_gas;
    std::optional<std::string> max_pri_fee_per_gas;
    std::optional<std::string> max_fee_per_blob_gas;
    std::optional<std::string> to;
    std::optional<std::monostate> nullto;
    std::optional<std::vector<GlazeJsonAccessList>> access_list;
    std::optional<std::vector<std::string>> blob_versioned_hashes;
    std::optional<std::vector<GlazeJsonAuthorization>> authorizations;

    struct glaze {
        using T = GlazeJsonTransaction;
        // NOLINTNEXTLINE(readability-identifier-naming)
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
            "maxFeePerBlobGas", &T::max_fee_per_blob_gas,
            "blobVersionedHashes", &T::blob_versioned_hashes,
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
            "blockNumber", &T::block_num,
            "gasPrice", &T::gas_price,
            "authorizations", &T::authorizations);
    };
};

void to_json(nlohmann::json& json, const Transaction& transaction);

void make_glaze_json_transaction(const silkworm::Transaction& tx, GlazeJsonTransaction& json_tx);

void make_glaze_json_content(const nlohmann::json& request_json, const Transaction& tx, std::string& json_reply);

}  // namespace silkworm::rpc
