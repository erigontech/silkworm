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

#include "transaction.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/silkrpc/common/compatibility.hpp>
#include <silkworm/silkrpc/common/util.hpp>

#include "filter.hpp"

namespace silkworm {

void to_json(nlohmann::json& json, const Transaction& transaction) {
    if (!transaction.from) {
        (const_cast<Transaction&>(transaction)).recover_sender();
    }
    if (transaction.from) {
        json["from"] = transaction.from.value();
    }
    json["gas"] = rpc::to_quantity(transaction.gas_limit);
    auto ethash_hash{hash_of_transaction(transaction)};
    json["hash"] = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    json["input"] = "0x" + silkworm::to_hex(transaction.data);
    json["nonce"] = rpc::to_quantity(transaction.nonce);
    if (transaction.to) {
        json["to"] = transaction.to.value();
    } else {
        json["to"] = nullptr;
    }
    json["type"] = rpc::to_quantity(uint64_t(transaction.type));

    if (transaction.type == silkworm::TransactionType::kDynamicFee) {
        json["maxPriorityFeePerGas"] = rpc::to_quantity(transaction.max_priority_fee_per_gas);
        json["maxFeePerGas"] = rpc::to_quantity(transaction.max_fee_per_gas);
    }
    if (transaction.type != silkworm::TransactionType::kLegacy) {
        json["chainId"] = rpc::to_quantity(*transaction.chain_id);
        json["v"] = rpc::to_quantity(uint64_t(transaction.odd_y_parity));
        json["accessList"] = transaction.access_list;  // EIP2930
        // Erigon currently at 2.48.1 does not yet support yParity field
        if (not rpc::compatibility::is_erigon_json_api_compatibility_required()) {
            json["yParity"] = rpc::to_quantity(transaction.odd_y_parity);
        }
    } else if (transaction.chain_id) {
        json["chainId"] = rpc::to_quantity(*transaction.chain_id);
        json["v"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    } else {
        json["v"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    }
    json["value"] = rpc::to_quantity(transaction.value);
    json["r"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.r));
    json["s"] = rpc::to_quantity(silkworm::endian::to_big_compact(transaction.s));
}

}  // namespace silkworm

namespace silkworm::rpc {

void make_glaze_json_transaction(const silkworm::Transaction& tx, GlazeJsonTransaction& json_tx) {
    if (!tx.from) {
        (const_cast<silkworm::Transaction&>(tx)).recover_sender();
    }
    if (tx.from) {
        to_hex(std::span(json_tx.from), tx.from.value().bytes);
    }

    if (tx.to) {
        json_tx.to = std::make_optional("0x" + silkworm::to_hex(tx.to.value().bytes));
    } else {
        std::monostate null_value{};
        json_tx.nullto = std::make_optional(std::move(null_value));
    }
    to_quantity(std::span(json_tx.gas), tx.gas_limit);
    auto ethash_hash{hash_of_transaction(tx)};
    auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    to_hex(std::span(json_tx.hash), bytes32_hash.bytes);
    json_tx.input.reserve(tx.data.size() * 2 + 3);
    json_tx.input = "0x" + silkworm::to_hex(tx.data);
    to_quantity(std::span(json_tx.nonce), tx.nonce);
    to_quantity(std::span(json_tx.type), uint64_t(tx.type));

    if (tx.type != silkworm::TransactionType::kLegacy) {
        json_tx.chain_id = std::make_optional(to_quantity(*tx.chain_id));
        to_quantity(std::span(json_tx.v), uint64_t(tx.odd_y_parity));

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

        //  Erigon currently at 2.48.1 does not yet support yParity field
        if (not rpc::compatibility::is_erigon_json_api_compatibility_required()) {
            json_tx.yparity = std::make_optional(rpc::to_quantity(tx.odd_y_parity));
        }
    } else if (tx.chain_id) {
        json_tx.chain_id = std::make_optional(to_quantity(*tx.chain_id));
        to_quantity(std::span(json_tx.v), silkworm::endian::to_big_compact(tx.v()));
    } else {
        rpc::to_quantity(std::span(json_tx.v), silkworm::endian::to_big_compact(tx.v()));
    }
    if (tx.type == silkworm::TransactionType::kDynamicFee) {
        json_tx.max_pri_fee_per_gas = std::make_optional(rpc::to_quantity(tx.max_priority_fee_per_gas));
        json_tx.max_fee_per_gas = std::make_optional(rpc::to_quantity(tx.max_fee_per_gas));
    }
    to_quantity(std::span(json_tx.value), tx.value);
    to_quantity(std::span(json_tx.r), silkworm::endian::to_big_compact(tx.r));
    to_quantity(std::span(json_tx.s), silkworm::endian::to_big_compact(tx.s));
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
        json["blockNumber"] = to_quantity(transaction.block_number);
        json["transactionIndex"] = to_quantity(transaction.transaction_index);
    }
}

}  // namespace silkworm::rpc
