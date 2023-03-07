/*
    Copyright 2020 The Silkrpc Authors

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

#include "types.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include <boost/endian/conversion.hpp>
#include <intx/intx.hpp>
#include <silkworm/core/common/util.hpp>

#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/core/common/endian.hpp>

namespace silkrpc {

using evmc::literals::operator""_address;

std::string to_hex_no_leading_zeros(silkworm::ByteView bytes) {
    static const char* kHexDigits{"0123456789abcdef"};

    std::string out{};

    if (bytes.length() == 0) {
       out.reserve(1);
       out.push_back('0');
       return out;
    }

    out.reserve(2 * bytes.length());

    bool found_nonzero{false};
    for (size_t i{0}; i < bytes.length(); ++i) {
        uint8_t x{bytes[i]};
        char lo{kHexDigits[x & 0x0f]};
        char hi{kHexDigits[x >> 4]};
        if (!found_nonzero && hi != '0') {
            found_nonzero = true;
        }
        if (found_nonzero) {
            out.push_back(hi);
        }
        if (!found_nonzero && lo != '0') {
            found_nonzero = true;
        }
        if (found_nonzero || i == bytes.length() - 1) {
            out.push_back(lo);
        }
    }

    return out;
}

std::string to_hex_no_leading_zeros(uint64_t number) {
    silkworm::Bytes number_bytes(8, '\0');
    boost::endian::store_big_u64(&number_bytes[0], number);
    return to_hex_no_leading_zeros(number_bytes);
}

std::string to_quantity(silkworm::ByteView bytes) {
    return "0x" + to_hex_no_leading_zeros(bytes);
}

std::string to_quantity(uint64_t number) {
    return "0x" + to_hex_no_leading_zeros(number);
}

std::string to_quantity(intx::uint256 number) {
    if (number == 0) {
       return "0x0";
    }
    return silkrpc::to_quantity(silkworm::endian::to_big_compact(number));
}

} // namespace silkrpc

namespace evmc {

void to_json(nlohmann::json& json, const address& addr) {
    json = "0x" + silkworm::to_hex(addr);
}

void from_json(const nlohmann::json& json, address& addr) {
    const auto address_bytes = silkworm::from_hex(json.get<std::string>());
    addr = silkworm::to_evmc_address(address_bytes.value_or(silkworm::Bytes{}));
}

void to_json(nlohmann::json& json, const bytes32& b32) {
    json = "0x" + silkworm::to_hex(b32);
}

void from_json(const nlohmann::json& json, bytes32& b32) {
    const auto b32_bytes = silkworm::from_hex(json.get<std::string>());
    b32 = silkworm::to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
}

} // namespace evmc

namespace intx {

void from_json(const nlohmann::json& json, uint256& ui256) {
    ui256 = intx::from_string<intx::uint256>(json.get<std::string>());
}

} // namespace intx

namespace silkworm {

void from_json(const nlohmann::json& json, AccessListEntry& entry) {
    entry.account =  json.at("address").get<evmc::address>();
    entry.storage_keys = json.at("storageKeys").get<std::vector<evmc::bytes32>>();
}

void to_json(nlohmann::json& json, const BlockHeader& header) {
    const auto block_number = silkrpc::to_quantity(header.number);
    json["number"] = block_number;
    json["hash"] = silkrpc::to_quantity(header.hash());
    json["parentHash"] = header.parent_hash;
    json["nonce"] = "0x" + silkworm::to_hex({header.nonce.data(), header.nonce.size()});
    json["sha3Uncles"] = header.ommers_hash;
    json["logsBloom"] = "0x" + silkworm::to_hex(silkrpc::full_view(header.logs_bloom));
    json["transactionsRoot"] = header.transactions_root;
    json["stateRoot"] = header.state_root;
    json["receiptsRoot"] = header.receipts_root;
    json["miner"] = header.beneficiary;
    json["difficulty"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(header.difficulty));
    json["extraData"] = "0x" + silkworm::to_hex(header.extra_data);
    json["mixHash"]= header.mix_hash;
    json["gasLimit"] = silkrpc::to_quantity(header.gas_limit);
    json["gasUsed"] = silkrpc::to_quantity(header.gas_used);
    json["timestamp"] = silkrpc::to_quantity(header.timestamp);
    if (header.base_fee_per_gas.has_value()) {
       json["baseFeePerGas"] = silkrpc::to_quantity(header.base_fee_per_gas.value_or(0));
    } else {
       json["baseFeePerGas"] = nullptr;
    }
    json["withdrawalsRoot"] = nullptr;  // waiting EIP-4895
}

void to_json(nlohmann::json& json, const AccessListEntry& access_list) {
    json["address"] = access_list.account;
    json["storageKeys"] = access_list.storage_keys;
}

void to_json(nlohmann::json& json, const Transaction& transaction) {
    if (!transaction.from) {
        (const_cast<Transaction&>(transaction)).recover_sender();
    }
    if (transaction.from) {
        json["from"] = transaction.from.value();
    }
    json["gas"] = silkrpc::to_quantity(transaction.gas_limit);
    auto ethash_hash{hash_of_transaction(transaction)};
    json["hash"] = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    json["input"] = "0x" + silkworm::to_hex(transaction.data);
    json["nonce"] = silkrpc::to_quantity(transaction.nonce);
    if (transaction.to) {
        json["to"] =  transaction.to.value();
    } else {
        json["to"] =  nullptr;
    }
    json["type"] = silkrpc::to_quantity((uint64_t)transaction.type);

    if (transaction.type == silkworm::Transaction::Type::kEip1559) {
       json["maxPriorityFeePerGas"] = silkrpc::to_quantity(transaction.max_priority_fee_per_gas);
       json["maxFeePerGas"] = silkrpc::to_quantity(transaction.max_fee_per_gas);
    }
    if (transaction.type != silkworm::Transaction::Type::kLegacy) {
       json["chainId"] = silkrpc::to_quantity(*transaction.chain_id);
       json["v"] = silkrpc::to_quantity((uint64_t)transaction.odd_y_parity);
       json["accessList"] = transaction.access_list; // EIP2930
    } else if (transaction.chain_id) {
       json["chainId"] = silkrpc::to_quantity(*transaction.chain_id);
       json["v"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    } else {
       json["v"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(transaction.v()));
    }
    json["value"] = silkrpc::to_quantity(transaction.value);
    json["r"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(transaction.r));
    json["s"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(transaction.s));
}


} // namespace silkworm

namespace silkrpc {

void to_json(nlohmann::json& json, const ChainTraffic& chain_traffic) {
    json["cumulativeGasUsed"] = to_quantity(chain_traffic.cumulative_gas_used);
    json["cumulativeTransactionsCount"] = to_quantity(chain_traffic.cumulative_transactions_count);
}

void to_json(nlohmann::json& json, const StageData& stage_data) {
    json["stage_name"] = stage_data.stage_name;
    json["block_number"] = stage_data.block_number;
}

void to_json(nlohmann::json& json, const SyncingData& syncing_data) {
    json["currentBlock"] = syncing_data.current_block;
    json["highestBlock"] = syncing_data.highest_block;
    json["stages"] = syncing_data.stages;
}

void to_json(nlohmann::json& json, const struct TxPoolStatusInfo& status_info) {
    json["queued"] = silkrpc::to_quantity(status_info.queued);
    json["pending"] = silkrpc::to_quantity(status_info.pending);
    json["baseFee"] = silkrpc::to_quantity(status_info.base_fee);
}

void to_json(nlohmann::json& json, const Rlp& rlp) {
    json = "0x" + silkworm::to_hex(rlp.buffer);
}

void to_json(nlohmann::json& json, const NodeInfoPorts& node_info_ports) {
    json["discovery"] = node_info_ports.discovery;
    json["listener"] = node_info_ports.listener;
}

void to_json(nlohmann::json& json, const NodeInfo& node_info) {
    json["id"] = node_info.id;
    json["name"] = node_info.name;
    json["enode"] = node_info.enode;
    json["enr"] = node_info.enr;
    json["listenAddr"] = node_info.listener_addr;
    json["ports"] = node_info.ports;
    json["ip"] = node_info.enode;
    json["protocols"] = nlohmann::json::parse(node_info.protocols, nullptr, /* allow_exceptions = */ false);
}

void to_json(nlohmann::json& json, const struct CallBundleTxInfo& tx_info) {
    json["gasUsed"] = tx_info.gas_used;
    json["txHash"] = silkworm::to_bytes32({tx_info.hash.bytes, silkworm::kHashLength});
    if (tx_info.error_message.size() != 0)
       json["error"] = tx_info.error_message;
    else
       json["value"] = silkworm::to_bytes32({tx_info.value.bytes, silkworm::kHashLength});
}

void to_json(nlohmann::json& json, const struct CallBundleInfo& bundle_info) {
    json["bundleHash"] = silkworm::to_bytes32({bundle_info.bundle_hash.bytes, silkworm::kHashLength});
    json["results"] = bundle_info.txs_info;
}


void to_json(nlohmann::json& json, const AccessListResult& access_list_result) {
    json["accessList"] = access_list_result.access_list;
    if (access_list_result.error) {
        json["error"] = *(access_list_result.error);
    }
    json["gasUsed"] = silkrpc::to_quantity(access_list_result.gas_used);
}

void to_json(nlohmann::json& json, const Block& b) {
    const auto block_number = silkrpc::to_quantity(b.block.header.number);
    json["number"] = block_number;
    json["hash"] = b.hash;
    json["parentHash"] = b.block.header.parent_hash;
    json["nonce"] = "0x" + silkworm::to_hex({b.block.header.nonce.data(), b.block.header.nonce.size()});
    json["sha3Uncles"] = b.block.header.ommers_hash;
    json["logsBloom"] = "0x" + silkworm::to_hex(full_view(b.block.header.logs_bloom));
    json["transactionsRoot"] = b.block.header.transactions_root;
    json["stateRoot"] = b.block.header.state_root;
    json["receiptsRoot"] = b.block.header.receipts_root;
    json["miner"] = b.block.header.beneficiary;
    json["difficulty"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(b.block.header.difficulty));
    json["totalDifficulty"] = silkrpc::to_quantity(silkworm::endian::to_big_compact(b.total_difficulty));
    json["extraData"] = "0x" + silkworm::to_hex(b.block.header.extra_data);
    json["mixHash"]= b.block.header.mix_hash;
    json["size"] = silkrpc::to_quantity(b.get_block_size());
    json["gasLimit"] = silkrpc::to_quantity(b.block.header.gas_limit);
    json["gasUsed"] = silkrpc::to_quantity(b.block.header.gas_used);
    if (b.block.header.base_fee_per_gas.has_value()) {
       json["baseFeePerGas"] = silkrpc::to_quantity(b.block.header.base_fee_per_gas.value_or(0));
    }
    json["timestamp"] = silkrpc::to_quantity(b.block.header.timestamp);
    if (b.full_tx) {
        json["transactions"] = b.block.transactions;
        for (auto i{0}; i < json["transactions"].size(); i++) {
            auto& json_txn = json["transactions"][i];
            json_txn["transactionIndex"] = silkrpc::to_quantity(i);
            json_txn["blockHash"] = b.hash;
            json_txn["blockNumber"] = block_number;
            json_txn["gasPrice"] = silkrpc::to_quantity(b.block.transactions[i].effective_gas_price(b.block.header.base_fee_per_gas.value_or(0)));
        }
    } else {
        std::vector<evmc::bytes32> transaction_hashes;
        transaction_hashes.reserve(b.block.transactions.size());
        for (auto i{0}; i < b.block.transactions.size(); i++) {
            auto ethash_hash{hash_of_transaction(b.block.transactions[i])};
            auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
            transaction_hashes.emplace(transaction_hashes.end(), std::move(bytes32_hash));
            SILKRPC_DEBUG << "transaction_hashes[" << i << "]: " << silkworm::to_hex({transaction_hashes[i].bytes, silkworm::kHashLength}) << "\n";
        }
        json["transactions"] = transaction_hashes;
    }
    std::vector<evmc::bytes32> ommer_hashes;
    ommer_hashes.reserve(b.block.ommers.size());
    for (auto i{0}; i < b.block.ommers.size(); i++) {
        ommer_hashes.emplace(ommer_hashes.end(), std::move(b.block.ommers[i].hash()));
        SILKRPC_DEBUG << "ommer_hashes[" << i << "]: " << silkworm::to_hex({ommer_hashes[i].bytes, silkworm::kHashLength}) << "\n";
    }
    json["uncles"] = ommer_hashes;
}

void to_json(nlohmann::json& json, const Transaction& transaction) {
    to_json(json, silkworm::Transaction(transaction));

    json["gasPrice"] = silkrpc::to_quantity(transaction.effective_gas_price());
    if (transaction.queued_in_pool) {
        json["blockHash"] = nullptr;
        json["blockNumber"] = nullptr;
        json["transactionIndex"] = nullptr;
    } else {
        json["blockHash"] = transaction.block_hash;
        json["blockNumber"] = silkrpc::to_quantity(transaction.block_number);
        json["transactionIndex"] = silkrpc::to_quantity(transaction.transaction_index);
    }
}

void from_json(const nlohmann::json& json, Call& call) {
    if (json.count("from") != 0) {
        call.from = json.at("from").get<evmc::address>();
    }
    if (json.count("to") != 0) {
        const auto to = json.at("to");
        if (!to.is_null()) {
            call.to = json.at("to").get<evmc::address>();
        }
    }
    if (json.count("nonce") != 0) {
        const auto json_nonce = json.at("nonce");
        if (json_nonce.is_string()) {
            call.nonce = std::stol(json_nonce.get<std::string>(), 0, 16);
        } else {
            call.nonce = json_nonce.get<uint64_t>();
        }
    }
    if (json.count("gas") != 0) {
        auto json_gas = json.at("gas");
        if (json_gas.is_string()) {
            call.gas = std::stol(json_gas.get<std::string>(), 0, 16);
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

void to_json(nlohmann::json& json, const Log& log) {
    json["address"] = log.address;
    json["topics"] = log.topics;
    json["data"] = "0x" + silkworm::to_hex(log.data);
    json["blockNumber"] = silkrpc::to_quantity(log.block_number);
    json["blockHash"] = log.block_hash;
    json["transactionHash"] = log.tx_hash;
    json["transactionIndex"] = silkrpc::to_quantity(log.tx_index);
    json["logIndex"] = silkrpc::to_quantity(log.index);
    json["removed"] = log.removed;
}

void from_json(const nlohmann::json& json, Log& log) {
    if (json.is_array()) {
        if (json.size() < 3) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: missing entries"};
        }
        if (!json[0].is_binary()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: binary expected in [0]"};
        }
        auto address_bytes = json[0].get_binary();
        log.address = silkworm::to_evmc_address(silkworm::Bytes{address_bytes.begin(), address_bytes.end()});
        if (!json[1].is_array()) {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: array expected in [1]"};
        }
        std::vector<evmc::bytes32> topics{};
        topics.reserve(json[1].size());
        for (auto topic : json[1]) {
            auto topic_bytes = topic.get_binary();
            topics.push_back(silkworm::to_bytes32(silkworm::Bytes{topic_bytes.begin(), topic_bytes.end()}));
        }
        log.topics = topics;
        if (json[2].is_binary()) {
            auto data_bytes = json[2].get_binary();
            log.data = silkworm::Bytes{data_bytes.begin(), data_bytes.end()};
        } else if (json[2].is_null()) {
            log.data = silkworm::Bytes{};
        } else {
            throw std::system_error{std::make_error_code(std::errc::invalid_argument), "Log CBOR: binary or null expected in [2]"};
        }
    } else {
        log.address = json.at("address").get<evmc::address>();
        log.topics = json.at("topics").get<std::vector<evmc::bytes32>>();
        log.data = json.at("data").get<silkworm::Bytes>();
    }
}

void to_json(nlohmann::json& json, const Receipt& receipt) {
    json["blockHash"] = receipt.block_hash;
    json["blockNumber"] = silkrpc::to_quantity(receipt.block_number);
    json["transactionHash"] = receipt.tx_hash;
    json["transactionIndex"] = silkrpc::to_quantity(receipt.tx_index);
    json["from"] = receipt.from.value_or(evmc::address{});
    json["to"] = receipt.to.value_or(evmc::address{});
    json["type"] = silkrpc::to_quantity(receipt.type ? receipt.type.value() : 0);
    json["gasUsed"] = silkrpc::to_quantity(receipt.gas_used);
    json["cumulativeGasUsed"] = silkrpc::to_quantity(receipt.cumulative_gas_used);
    json["effectiveGasPrice"] = silkrpc::to_quantity(receipt.effective_gas_price);
    if (receipt.contract_address) {
        json["contractAddress"] = receipt.contract_address;
    } else {
        json["contractAddress"] = nlohmann::json{};
    }
    json["logs"] = receipt.logs;
    json["logsBloom"] = "0x" + silkworm::to_hex(full_view(receipt.bloom));
    json["status"] = silkrpc::to_quantity(receipt.success ? 1 : 0);
}

void from_json(const nlohmann::json& json, Receipt& receipt) {
    SILKRPC_TRACE << "from_json<Receipt> json: " << json.dump() << "\n";
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

void to_json(nlohmann::json& json, const Filter& filter) {
    if (filter.from_block != std::nullopt) {
        json["fromBlock"] = filter.from_block.value();
    }
    if (filter.to_block != std::nullopt) {
        json["toBlock"] = filter.to_block.value();
    }
    if (filter.addresses != std::nullopt) {
        if (filter.addresses.value().size() == 1) {
            json["address"] = filter.addresses.value()[0];
        } else {
            json["address"] = filter.addresses.value();
        }
    }
    if (filter.topics != std::nullopt) {
        json["topics"] = filter.topics.value();
    }
    if (filter.block_hash != std::nullopt) {
        json["blockHash"] = filter.block_hash.value();
    }
}

void from_json(const nlohmann::json& json, Filter& filter) {
    if (json.count("fromBlock") != 0) {
        auto json_from_block = json.at("fromBlock");
        if (json_from_block.is_string()) {
            filter.from_block = json_from_block.get<std::string>();
        } else {
            filter.from_block = to_quantity(json_from_block.get<uint64_t>());
        }
    }
    if (json.count("toBlock") != 0) {
        auto json_to_block = json.at("toBlock");
        if (json_to_block.is_string()) {
            filter.to_block = json_to_block.get<std::string>();
        } else {
            filter.to_block = to_quantity(json_to_block.get<uint64_t>());
        }
    }
    if (json.count("address") != 0) {
        if (json.at("address").is_string()) {
            filter.addresses = {json.at("address").get<evmc::address>()};
        } else {
            filter.addresses = json.at("address").get<FilterAddresses>();
        }
    }
    if (json.count("topics") != 0) {
        auto topics = json.at("topics");
        if (topics != nlohmann::detail::value_t::null) {
            for (auto& topic_item : topics) {
                if (topic_item.is_null()) {
                    topic_item = FilterSubTopics{};
                }
                if (topic_item.is_string()) {
                    topic_item = FilterSubTopics{topic_item};
                }
            }
            filter.topics = topics.get<FilterTopics>();
        }
    }
    if (json.count("blockHash") != 0) {
        filter.block_hash = json.at("blockHash").get<std::string>();
    }
}

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
    json["blockNumber"] = silkrpc::to_quantity(execution_payload.number);
    json["gasLimit"] = silkrpc::to_quantity(execution_payload.gas_limit);
    json["gasUsed"] = silkrpc::to_quantity(execution_payload.gas_used);
    json["timestamp"] = silkrpc::to_quantity(execution_payload.timestamp);
    json["extraData"] = "0x" + silkworm::to_hex(execution_payload.extra_data);
    json["baseFeePerGas"] = silkrpc::to_quantity(execution_payload.base_fee);
    json["blockHash"] = execution_payload.block_hash;
    json["transactions"] = transaction_list;
}

void from_json(const nlohmann::json& json, ExecutionPayload& execution_payload) {
    // Parse logs bloom
    silkworm::Bloom logs_bloom;
    std::memcpy(&logs_bloom[0],
                silkworm::from_hex(json.at("logsBloom").get<std::string>())->data(),
                silkworm::kBloomByteLength
    );
    // Parse transactions
    std::vector<silkworm::Bytes> transactions;
    for (const auto& hex_transaction : json.at("transactions")) {
        transactions.push_back(
            *silkworm::from_hex(hex_transaction.get<std::string>())
        );
    }

    execution_payload = ExecutionPayload{
        .number = static_cast<uint64_t>(std::stol(json.at("blockNumber").get<std::string>(), 0, 16)),
        .timestamp = static_cast<uint64_t>(std::stol(json.at("timestamp").get<std::string>(), 0, 16)),
        .gas_limit = static_cast<uint64_t>(std::stol(json.at("gasLimit").get<std::string>(), 0, 16)),
        .gas_used = static_cast<uint64_t>(std::stol(json.at("gasUsed").get<std::string>(), 0, 16)),
        .suggested_fee_recipient = json.at("feeRecipient").get<evmc::address>(),
        .state_root = json.at("stateRoot").get<evmc::bytes32>(),
        .receipts_root = json.at("receiptsRoot").get<evmc::bytes32>(),
        .parent_hash = json.at("parentHash").get<evmc::bytes32>(),
        .block_hash = json.at("blockHash").get<evmc::bytes32>(),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .base_fee = json.at("baseFeePerGas").get<intx::uint256>(),
        .logs_bloom = logs_bloom,
        .extra_data = *silkworm::from_hex(json.at("extraData").get<std::string>()),
        .transactions = transactions
    };
}

void to_json(nlohmann::json& json, const ForkChoiceState& forkchoice_state) {
    json["headBlockHash"] = forkchoice_state.head_block_hash;
    json["safeBlockHash"] = forkchoice_state.safe_block_hash;
    json["finalizedBlockHash"] = forkchoice_state.finalized_block_hash;
}

void from_json(const nlohmann::json& json, ForkChoiceState& forkchoice_state) {
    forkchoice_state = ForkChoiceState{
        .head_block_hash = json.at("headBlockHash").get<evmc::bytes32>(),
        .safe_block_hash = json.at("safeBlockHash").get<evmc::bytes32>(),
        .finalized_block_hash = json.at("finalizedBlockHash").get<evmc::bytes32>()
    };
}

void to_json(nlohmann::json& json, const PayloadAttributes& payload_attributes) {
    json["timestamp"] = silkrpc::to_quantity(payload_attributes.timestamp);
    json["prevRandao"] = payload_attributes.prev_randao;
    json["feeRecipient"] = payload_attributes.suggested_fee_recipient;
}

void from_json(const nlohmann::json& json, PayloadAttributes& payload_attributes) {
    payload_attributes = PayloadAttributes{
        .timestamp = static_cast<uint64_t>(std::stol(json.at("timestamp").get<std::string>(), 0, 16)),
        .prev_randao = json.at("prevRandao").get<evmc::bytes32>(),
        .suggested_fee_recipient = json.at("feeRecipient").get<evmc::address>(),
    };
}

void to_json(nlohmann::json& json, const ForkChoiceUpdatedReply& forkchoice_updated_reply) {
    nlohmann::json json_payload_status = forkchoice_updated_reply.payload_status;
    json["payloadStatus"] = json_payload_status;
    if (forkchoice_updated_reply.payload_id != std::nullopt) {
        json["payloadId"] = silkrpc::to_quantity(forkchoice_updated_reply.payload_id.value());
    }
}

void to_json(nlohmann::json& json, const PayloadStatus& payload_status) {
    json["status"] = payload_status.status;

    if (payload_status.latest_valid_hash) {
        json["latestValidHash"] = *payload_status.latest_valid_hash;
    }
    if (payload_status.validation_error) {
        json["validationError"] = *payload_status.validation_error;
    }
}

void to_json(nlohmann::json& json, const TransitionConfiguration& transition_configuration) {
    json["terminalTotalDifficulty"] = silkrpc::to_quantity(transition_configuration.terminal_total_difficulty);
    json["terminalBlockHash"] = transition_configuration.terminal_block_hash;
    json["terminalBlockNumber"] = silkrpc::to_quantity(transition_configuration.terminal_block_number);
}

void from_json(const nlohmann::json& json, TransitionConfiguration& transition_configuration) {
    transition_configuration = TransitionConfiguration {
        .terminal_total_difficulty = json.at("terminalTotalDifficulty").get<intx::uint256>(),
        .terminal_block_hash = json.at("terminalBlockHash").get<evmc::bytes32>(),
        .terminal_block_number = static_cast<uint64_t>(std::stol(json.at("terminalBlockNumber").get<std::string>(), 0, 16))
    };
}

void to_json(nlohmann::json& json, const Forks& forks) {
    json["genesis"] = forks.genesis_hash;
    json["forks"] = forks.block_numbers;
}

void to_json(nlohmann::json& json, const Issuance& issuance) {
    if (issuance.block_reward) {
        json["blockReward"] = issuance.block_reward.value();
    } else {
        json["blockReward"] = nullptr;
    }
    if (issuance.ommer_reward) {
        json["uncleReward"] = issuance.ommer_reward.value();
    } else {
        json["uncleReward"] = nullptr;
    }
    if (issuance.issuance) {
        json["issuance"] = issuance.issuance.value();
    } else {
        json["issuance"] = nullptr;
    }
    if (issuance.burnt) {
        json["burnt"] = issuance.burnt.value();
    } else {
        json["burnt"] = nullptr;
    }
    if (issuance.total_issued) {
        json["totalIssued"] = issuance.total_issued.value();
    } else {
        json["totalIssued"] = nullptr;
    }
    if (issuance.total_burnt) {
        json["totalBurnt"] = issuance.total_burnt.value();
    } else {
        json["totalBurnt"] = nullptr;
    }
    if (issuance.tips) {
        json["tips"] = issuance.tips.value();
    } else {
        json["tips"] = nullptr;
    }
}

void to_json(nlohmann::json& json, const Error& error) {
    json = {{"code", error.code}, {"message", error.message}};
}

void to_json(nlohmann::json& json, const RevertError& error) {
    json = {{"code", error.code}, {"message", error.message}, {"data", "0x" + silkworm::to_hex(error.data)}};
}

void to_json(nlohmann::json& json, const std::set<evmc::address>& addresses) {
    json = nlohmann::json::array();
    for (const auto& address : addresses) {
        json.push_back("0x" + silkworm::to_hex(address));
    }
}

nlohmann::json make_json_content(uint32_t id) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"result", nullptr}};
}

nlohmann::json make_json_content(uint32_t id, const nlohmann::json& result) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"result", result}};
}

nlohmann::json make_json_error(uint32_t id, int32_t code, const std::string& message) {
    const Error error{code, message};
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", error}};
}

nlohmann::json make_json_error(uint32_t id, const RevertError& error) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", error}};
}

} // namespace silkrpc
