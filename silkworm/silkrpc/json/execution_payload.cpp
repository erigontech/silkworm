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

#include <cstring>
#include <utility>

#include <silkworm/core/common/util.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>

#include "filter.hpp"
#include "types.hpp"

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
    json["blockNumber"] = to_quantity(execution_payload.number);
    json["gasLimit"] = to_quantity(execution_payload.gas_limit);
    json["gasUsed"] = to_quantity(execution_payload.gas_used);
    json["timestamp"] = to_quantity(execution_payload.timestamp);
    json["extraData"] = "0x" + silkworm::to_hex(execution_payload.extra_data);
    json["baseFeePerGas"] = to_quantity(execution_payload.base_fee);
    json["blockHash"] = execution_payload.block_hash;
    json["transactions"] = transaction_list;
}

void from_json(const nlohmann::json& json, ExecutionPayload& execution_payload) {
    // Parse logs bloom
    silkworm::Bloom logs_bloom;
    std::memcpy(&logs_bloom[0],
                silkworm::from_hex(json.at("logsBloom").get<std::string>())->data(),
                silkworm::kBloomByteLength);
    // Parse transactions
    std::vector<silkworm::Bytes> transactions;
    for (const auto& hex_transaction : json.at("transactions")) {
        transactions.push_back(
            *silkworm::from_hex(hex_transaction.get<std::string>()));
    }

    execution_payload = ExecutionPayload{
        .number = static_cast<uint64_t>(std::stol(json.at("blockNumber").get<std::string>(), nullptr, 16)),
        .timestamp = static_cast<uint64_t>(std::stol(json.at("timestamp").get<std::string>(), nullptr, 16)),
        .gas_limit = static_cast<uint64_t>(std::stol(json.at("gasLimit").get<std::string>(), nullptr, 16)),
        .gas_used = static_cast<uint64_t>(std::stol(json.at("gasUsed").get<std::string>(), nullptr, 16)),
        .suggested_fee_recipient = json.at("feeRecipient").get<evmc::address>(),
        .state_root = json.at("stateRoot").get<evmc::bytes32>(),
        .receipts_root = json.at("receiptsRoot").get<evmc::bytes32>(),
        .parent_hash = json.at("parentHash").get<evmc::bytes32>(),
        .block_hash = json.at("blockHash").get<evmc::bytes32>(),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .base_fee = json.at("baseFeePerGas").get<intx::uint256>(),
        .logs_bloom = logs_bloom,
        .extra_data = *silkworm::from_hex(json.at("extraData").get<std::string>()),
        .transactions = transactions};
}

}  // namespace silkworm::rpc
