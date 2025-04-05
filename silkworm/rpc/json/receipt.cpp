// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const std::shared_ptr<Receipt> receipt) {
    json = *receipt;
}

void to_json(nlohmann::json& json, const Receipt& receipt) {
    json["blockHash"] = receipt.block_hash;
    json["blockNumber"] = to_quantity(receipt.block_num);
    json["transactionHash"] = receipt.tx_hash;
    json["transactionIndex"] = to_quantity(receipt.tx_index);
    json["from"] = receipt.from.value_or(evmc::address{});
    if (receipt.to) {
        json["to"] = *receipt.to;
    } else {
        json["to"] = nlohmann::json{};
    }
    json["type"] = to_quantity(static_cast<uint8_t>(receipt.type));
    json["gasUsed"] = to_quantity(receipt.gas_used);
    json["cumulativeGasUsed"] = to_quantity(receipt.cumulative_gas_used);
    json["effectiveGasPrice"] = to_quantity(receipt.effective_gas_price);
    if (receipt.contract_address) {
        json["contractAddress"] = receipt.contract_address;
    } else {
        json["contractAddress"] = nlohmann::json{};
    }
    json["logs"] = receipt.logs;
    json["logsBloom"] = "0x" + silkworm::to_hex(full_view(receipt.bloom));
    json["status"] = to_quantity(receipt.success ? 1 : 0);

    if (receipt.blob_gas_used) {
        json["blobGasUsed"] = to_quantity(*(receipt.blob_gas_used));
    }
    if (receipt.blob_gas_price) {
        json["blobGasPrice"] = to_quantity(*(receipt.blob_gas_price));
    }
}

void from_json(const nlohmann::json& json, std::shared_ptr<Receipt>& receipt) {
    SILK_TRACE << "from_json<Receipt> json: " << json.dump();
    if (json.is_array()) {
        if (json.size() < 4) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: missing entries"};
        }
        if (!json[0].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [0]"};
        }
        receipt = std::make_shared<Receipt>();
        receipt->type = json[0];

        if (!json[1].is_null()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: null expected in [1]"};
        }

        if (!json[2].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [2]"};
        }
        receipt->success = json[2] == 1u;

        if (!json[3].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [3]"};
        }
        receipt->cumulative_gas_used = json[3];
    } else {
        if (!json.contains("success") || !json.contains("cumulative_gas_used")) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: missing entries in " + json.dump()};
        }
        receipt = std::make_shared<Receipt>();
        receipt->success = json.at("success").get<bool>();
        receipt->cumulative_gas_used = json.at("cumulative_gas_used").get<uint64_t>();
    }
}

}  // namespace silkworm::rpc
