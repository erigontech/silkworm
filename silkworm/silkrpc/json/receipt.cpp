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

#include "receipt.hpp"

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Receipt& receipt) {
    json["blockHash"] = receipt.block_hash;
    json["blockNumber"] = to_quantity(receipt.block_number);
    json["transactionHash"] = receipt.tx_hash;
    json["transactionIndex"] = to_quantity(receipt.tx_index);
    json["from"] = receipt.from.value_or(evmc::address{});
    if (receipt.to) {
        json["to"] = *receipt.to;
    } else {
        json["to"] = nlohmann::json{};
    }
    json["type"] = to_quantity(receipt.type ? receipt.type.value() : 0);
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
}

void from_json(const nlohmann::json& json, Receipt& receipt) {
    SILK_TRACE << "from_json<Receipt> json: " << json.dump();
    if (json.is_array()) {
        if (json.size() < 4) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: missing entries"};
        }
        if (!json[0].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [0]"};
        }
        receipt.type = json[0];

        if (!json[1].is_null()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: null expected in [1]"};
        }

        if (!json[2].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [2]"};
        }
        receipt.success = json[2] == 1u;

        if (!json[3].is_number()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Receipt CBOR: number expected in [3]"};
        }
        receipt.cumulative_gas_used = json[3];
    } else {
        receipt.success = json.at("success").get<bool>();
        receipt.cumulative_gas_used = json.at("cumulative_gas_used").get<uint64_t>();
    }
}

void make_glaze_json_receipt(const Receipt& receipt, GlazeJsonReceipt& json_receipt) {
    to_quantity(std::span(json_receipt.block_number), receipt.block_number);
    to_hex(std::span(json_receipt.block_hash), receipt.block_hash.bytes);
    to_hex(std::span(json_receipt.transaction_hash), receipt.tx_hash.bytes);
    to_quantity(std::span(json_receipt.transaction_index), receipt.tx_index);
    to_hex(std::span(json_receipt.from), receipt.from.value_or(evmc::address{}).bytes);

    if (receipt.to) {
        json_receipt.to = std::make_optional("0x" + silkworm::to_hex(receipt.to.value().bytes));
    } else {
        std::monostate null_value{};
        json_receipt.nullto = std::make_optional(std::move(null_value));
    }

    to_quantity(std::span(json_receipt.type), receipt.type ? receipt.type.value() : 0);
    to_quantity(std::span(json_receipt.gas_used), receipt.gas_used);
    to_quantity(std::span(json_receipt.cumulative_gas_used), receipt.cumulative_gas_used);
    to_quantity(std::span(json_receipt.effective_gas_price), receipt.effective_gas_price);

    if (receipt.contract_address) {
        json_receipt.contract_address = std::make_optional("0x" + silkworm::to_hex(receipt.contract_address.bytes));
    } else {
        std::monostate null_value{};
        json_receipt.nullcontract_address = std::make_optional(std::move(null_value));
    }

    to_quantity(std::span(json_receipt.status), receipt.success ? 1 : 0);
}

}  // namespace silkworm::rpc
