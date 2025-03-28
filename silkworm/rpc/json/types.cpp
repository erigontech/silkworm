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

#include "types.hpp"

#include <cstring>
#include <span>
#include <utility>

#include <intx/intx.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/compatibility.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

void to_hex(std::span<char> hex_bytes, silkworm::ByteView bytes) {
    static constexpr const char* kHexDigits{"0123456789abcdef"};
    if (bytes.size() * 2 + 2 + 1 > hex_bytes.size()) {
        SILK_ERROR << "req buffer length: " << bytes.size() * 2 + 2 + 1 << "  buffer length: " << hex_bytes.size() << "\n";
        throw std::invalid_argument("to_hex: hex_bytes too small");
    }
    char* dest = hex_bytes.data();
    *dest++ = '0';
    *dest++ = 'x';
    for (const auto& b : bytes) {
        *dest++ = kHexDigits[b >> 4];    // Hi
        *dest++ = kHexDigits[b & 0x0f];  // Lo
    }
    *dest = '\0';
}

void to_hex_no_leading_zeros(std::span<char> hex_bytes, silkworm::ByteView bytes) {
    static constexpr const char* kHexDigits{"0123456789abcdef"};
    size_t len = bytes.length();
    if (len * 2 + 2 + 1 > hex_bytes.size()) {
        SILK_ERROR << "req buffer length: " << len * 2 + 2 + 1 << "  buffer length: " << hex_bytes.size() << "\n";
        throw std::invalid_argument("to_hex_no_leading_zeros: hex_bytes too small");
    }
    char* dest = hex_bytes.data();
    *dest++ = '0';
    *dest++ = 'x';

    bool found_nonzero{false};
    for (size_t i{0}; i < len; ++i) {
        auto x{bytes[i]};
        char lo{kHexDigits[x & 0x0f]};
        char hi{kHexDigits[x >> 4]};
        if (!found_nonzero && hi != '0') {
            found_nonzero = true;
        }
        if (found_nonzero) {
            *dest++ = hi;
        }
        if (!found_nonzero && lo != '0') {
            found_nonzero = true;
        }
        if (found_nonzero || i == len - 1) {
            *dest++ = lo;
        }
    }
    *dest = '\0';
}

void to_quantity(std::span<char> quantity_hex_bytes, silkworm::ByteView bytes) {
    to_hex_no_leading_zeros(quantity_hex_bytes, bytes);
}

void to_quantity(std::span<char> quantity_hex_bytes, BlockNum block_num) {
    silkworm::Bytes block_num_bytes(8, '\0');
    silkworm::endian::store_big_u64(block_num_bytes.data(), block_num);
    to_hex_no_leading_zeros(quantity_hex_bytes, block_num_bytes);
}

void to_quantity(std::span<char> quantity_hex_bytes, intx::uint256 number) {
    if (number == 0) {
        quantity_hex_bytes[0] = '0';
        quantity_hex_bytes[1] = 'x';
        quantity_hex_bytes[2] = '0';
        quantity_hex_bytes[3] = '\0';
        return;
    }
    to_quantity(quantity_hex_bytes, silkworm::endian::to_big_compact(number));
}

std::string to_hex_no_leading_zeros(silkworm::ByteView bytes) {
    static constexpr const char* kHexDigits{"0123456789abcdef"};

    std::string out{};

    if (bytes.empty()) {
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

uint64_t from_quantity(const std::string& hex_quantity) {
    return std::stoul(hex_quantity, nullptr, 16);
}

std::string to_hex(uint64_t number) {
    silkworm::Bytes number_bytes(8, '\0');
    endian::store_big_u64(&number_bytes[0], number);
    return silkworm::to_hex(number_bytes, /*with_prefix=*/true);
}

std::string to_hex_no_leading_zeros(uint64_t number) {
    silkworm::Bytes number_bytes(8, '\0');
    endian::store_big_u64(&number_bytes[0], number);
    return to_hex_no_leading_zeros(number_bytes);
}

std::string to_quantity(silkworm::ByteView bytes) {
    return "0x" + to_hex_no_leading_zeros(bytes);
}

std::string to_quantity(const evmc::bytes32& bytes) {
    return to_quantity(silkworm::ByteView{bytes.bytes});
}

std::string to_quantity(uint64_t number) {
    return "0x" + to_hex_no_leading_zeros(number);
}

std::string to_quantity(const intx::uint256& number) {
    if (number == 0) {
        return "0x0";
    }
    return to_quantity(silkworm::endian::to_big_compact(number));
}

}  // namespace silkworm::rpc

namespace evmc {

void to_json(nlohmann::json& json, const address& addr) {
    json = silkworm::address_to_hex(addr);
}

void from_json(const nlohmann::json& json, address& addr) {
    addr = silkworm::hex_to_address(json.get<std::string>(), /*return_zero_on_err=*/true);
}

void to_json(nlohmann::json& json, const bytes32& b32) {
    json = silkworm::to_hex(b32, true);
}

void from_json(const nlohmann::json& json, bytes32& b32) {
    const auto b32_bytes = silkworm::from_hex(json.get<std::string>());
    b32 = silkworm::to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
}

}  // namespace evmc

namespace intx {

void from_json(const nlohmann::json& json, uint256& ui256) {
    ui256 = intx::from_string<intx::uint256>(json.get<std::string>());
}

}  // namespace intx

namespace silkworm {

void to_json(nlohmann::json& json, const BlockHeader& header) {
    const auto block_num = rpc::to_quantity(header.number);
    json["number"] = block_num;
    json["hash"] = rpc::to_quantity(header.hash());
    json["parentHash"] = header.parent_hash;
    json["nonce"] = "0x" + silkworm::to_hex({header.nonce.data(), header.nonce.size()});
    json["sha3Uncles"] = header.ommers_hash;
    json["logsBloom"] = "0x" + silkworm::to_hex(silkworm::full_view(header.logs_bloom));
    json["transactionsRoot"] = header.transactions_root;
    json["stateRoot"] = header.state_root;
    json["receiptsRoot"] = header.receipts_root;
    json["miner"] = header.beneficiary;
    json["difficulty"] = rpc::to_quantity(silkworm::endian::to_big_compact(header.difficulty));
    json["extraData"] = "0x" + silkworm::to_hex(header.extra_data);
    json["mixHash"] = header.prev_randao;
    json["gasLimit"] = rpc::to_quantity(header.gas_limit);
    json["gasUsed"] = rpc::to_quantity(header.gas_used);
    json["timestamp"] = rpc::to_quantity(header.timestamp);
    if (header.base_fee_per_gas) {
        json["baseFeePerGas"] = rpc::to_quantity(header.base_fee_per_gas.value_or(0));
    } else {
        json["baseFeePerGas"] = nullptr;
    }
    if (rpc::compatibility::is_erigon_json_api_compatibility_required()) {
        json["AuRaSeal"] = nullptr;
        json["AuRaStep"] = 0;
        json["Verkle"] = false;
        json["VerkleKeyVals"] = nullptr;
        json["VerkleProof"] = nullptr;
        json["requestsHash"] = nullptr;
    }
    if (header.blob_gas_used) {
        json["blobGasUsed"] = rpc::to_quantity(*header.blob_gas_used);
    } else {
        json["blobGasUsed"] = nullptr;
    }
    if (header.excess_blob_gas) {
        json["excessBlobGas"] = rpc::to_quantity(*header.excess_blob_gas);
    } else {
        json["excessBlobGas"] = nullptr;
    }
    if (header.parent_beacon_block_root) {
        json["parentBeaconBlockRoot"] = "0x" + to_hex(*header.parent_beacon_block_root);
    } else {
        json["parentBeaconBlockRoot"] = nullptr;
    }
    if (header.withdrawals_root) {
        json["withdrawalsRoot"] = *header.withdrawals_root;
    } else {
        json["withdrawalsRoot"] = nullptr;
    }
    if (header.requests_hash) {
        json["requestsHash"] = "0x" + to_hex(*header.requests_hash);
    } else {
        json["requestsHash"] = nullptr;
    }
}

}  // namespace silkworm

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const ChainTraffic& chain_traffic) {
    json["cumulativeGasUsed"] = to_quantity(chain_traffic.cumulative_gas_used);
    json["cumulativeTransactionsCount"] = to_quantity(chain_traffic.cumulative_transactions_count);
}

void to_json(nlohmann::json& json, const StageData& stage_data) {
    json["stage_name"] = stage_data.stage_name;
    json["block_number"] = stage_data.block_num;
}

void to_json(nlohmann::json& json, const SyncingData& syncing_data) {
    json["currentBlock"] = syncing_data.current_block;
    json["highestBlock"] = syncing_data.max_block;
    json["stages"] = syncing_data.stages;
}

void to_json(nlohmann::json& json, const struct TxPoolStatusInfo& status_info) {
    json["queued"] = to_quantity(status_info.queued);
    json["pending"] = to_quantity(status_info.pending);
    json["baseFee"] = to_quantity(status_info.base_fee);
}

void to_json(nlohmann::json& json, const Rlp& rlp) {
    json = "0x" + silkworm::to_hex(rlp.buffer);
}

void to_json(nlohmann::json& json, const PeerInfo& info) {
    json["id"] = info.id;
    json["name"] = info.name;
    json["enode"] = info.enode;
    if (!info.enr.empty()) {
        json["enr"] = info.enr;
    }
    json["caps"] = info.caps;
    json["network"]["localAddress"] = info.local_address;
    json["network"]["remoteAddress"] = info.remote_address;
    json["network"]["inbound"] = info.is_connection_inbound;
    json["network"]["static"] = info.is_connection_static;
    json["network"]["trusted"] = info.is_connection_trusted;
    json["protocols"] = nullptr;
}

void to_json(nlohmann::json& json, const AccessListResult& access_list_result) {
    json["accessList"] = access_list_result.access_list;
    if (access_list_result.error) {
        json["error"] = *(access_list_result.error);
    }
    json["gasUsed"] = to_quantity(access_list_result.gas_used);
}

void to_json(nlohmann::json& json, const BlockDetailsResponse& b) {
    const auto block_num = to_quantity(b.block.header.number);
    json["block"]["number"] = block_num;
    json["block"]["difficulty"] = to_quantity(silkworm::endian::to_big_compact(b.block.header.difficulty));
    json["block"]["extraData"] = "0x" + silkworm::to_hex(b.block.header.extra_data);
    json["block"]["gasLimit"] = to_quantity(b.block.header.gas_limit);
    json["block"]["gasUsed"] = to_quantity(b.block.header.gas_used);
    json["block"]["hash"] = b.block.hash;
    json["block"]["logsBloom"] = nullptr;
    json["block"]["miner"] = b.block.header.beneficiary;
    json["block"]["mixHash"] = b.block.header.prev_randao;
    json["block"]["nonce"] = "0x" + silkworm::to_hex({b.block.header.nonce.data(), b.block.header.nonce.size()});
    json["block"]["parentHash"] = b.block.header.parent_hash;
    json["block"]["receiptsRoot"] = b.block.header.receipts_root;
    json["block"]["sha3Uncles"] = b.block.header.ommers_hash;
    json["block"]["size"] = to_quantity(b.block.block_size);
    json["block"]["stateRoot"] = b.block.header.state_root;
    json["block"]["timestamp"] = to_quantity(b.block.header.timestamp);
    json["block"]["transactionCount"] = b.block.transaction_count;  // to_quantity(b.block.transaction_count);
    json["block"]["transactionsRoot"] = b.block.header.transactions_root;
    if (b.block.header.base_fee_per_gas.has_value()) {
        json["block"]["baseFeePerGas"] = rpc::to_quantity(b.block.header.base_fee_per_gas.value_or(0));
    }

    std::vector<evmc::bytes32> ommer_hashes;
    ommer_hashes.reserve(b.block.ommers.size());
    for (size_t i{0}; i < b.block.ommers.size(); ++i) {
        ommer_hashes.emplace(ommer_hashes.end(), b.block.ommers[i].hash());
        SILK_DEBUG << "ommer_hashes[" << i << "]: " << silkworm::to_hex({ommer_hashes[i].bytes, silkworm::kHashLength});
    }
    json["block"]["uncles"] = ommer_hashes;

    if (b.issuance.total_reward > 0) {
        json["issuance"]["issuance"] = to_quantity(b.issuance.miner_reward);
        json["issuance"]["uncleReward"] = to_quantity(b.issuance.ommers_reward);
        json["issuance"]["blockReward"] = to_quantity(b.issuance.total_reward);
    } else {
        json["issuance"]["issuance"] = "0x0";
        json["issuance"]["uncleReward"] = "0x0";
        json["issuance"]["blockReward"] = "0x0";
    }

    json["totalFees"] = to_quantity(b.total_fees);

    if (b.block.header.blob_gas_used) {
        json["block"]["blobGasUsed"] = rpc::to_quantity(*b.block.header.blob_gas_used);
    }
    if (b.block.header.excess_blob_gas) {
        json["block"]["excessBlobGas"] = rpc::to_quantity(*b.block.header.excess_blob_gas);
    }
    if (b.block.header.parent_beacon_block_root) {
        json["block"]["parentBeaconBlockRoot"] = "0x" + silkworm::to_hex(*b.block.header.parent_beacon_block_root);
    }
    if (b.block.header.withdrawals_root) {
        json["block"]["withdrawalsRoot"] = *b.block.header.withdrawals_root;
    }
    if (b.block.withdrawals) {
        json["block"]["withdrawals"] = *b.block.withdrawals;
    }
    if (b.block.header.requests_hash) {
        json["block"]["requestsHash"] = *b.block.header.requests_hash;
    }
}

void to_json(nlohmann::json& json, const BlockTransactionsResponse& b) {
    const auto block_num = to_quantity(b.header.number);
    json["fullblock"]["difficulty"] = to_quantity(silkworm::endian::to_big_compact(b.header.difficulty));
    json["fullblock"]["extraData"] = "0x" + silkworm::to_hex(b.header.extra_data);
    json["fullblock"]["gasLimit"] = to_quantity(b.header.gas_limit);
    json["fullblock"]["gasUsed"] = to_quantity(b.header.gas_used);
    json["fullblock"]["hash"] = b.hash;
    json["fullblock"]["logsBloom"];
    json["fullblock"]["miner"] = b.header.beneficiary;
    json["fullblock"]["mixHash"] = b.header.prev_randao;
    json["fullblock"]["nonce"] = "0x" + silkworm::to_hex({b.header.nonce.data(), b.header.nonce.size()});
    json["fullblock"]["number"] = block_num;
    json["fullblock"]["parentHash"] = b.header.parent_hash;
    json["fullblock"]["receiptsRoot"] = b.header.receipts_root;
    json["fullblock"]["sha3Uncles"] = b.header.ommers_hash;
    json["fullblock"]["size"] = to_quantity(b.block_size);
    json["fullblock"]["stateRoot"] = b.header.state_root;
    json["fullblock"]["timestamp"] = to_quantity(b.header.timestamp);
    json["fullblock"]["transactionCount"] = b.transaction_count;
    if (b.header.base_fee_per_gas) {
        json["fullblock"]["baseFeePerGas"] = rpc::to_quantity(b.header.base_fee_per_gas.value_or(0));
    }
    if (b.header.withdrawals_root) {
        json["fullblock"]["withdrawalsRoot"] = *b.header.withdrawals_root;
    }

    if (b.withdrawals) {
        json["fullblock"]["withdrawals"] = *(b.withdrawals);
    }

    if (b.header.blob_gas_used) {
        json["fullblock"]["blobGasUsed"] = rpc::to_quantity(*b.header.blob_gas_used);
    }
    if (b.header.excess_blob_gas) {
        json["fullblock"]["excessBlobGas"] = rpc::to_quantity(*b.header.excess_blob_gas);
    }
    if (b.header.parent_beacon_block_root) {
        json["fullblock"]["parentBeaconBlockRoot"] = silkworm::to_hex(*b.header.parent_beacon_block_root, /* with_prefix = */ true);
    }
    if (b.header.requests_hash) {
        json["fullblock"]["requestsHash"] = silkworm::to_hex(*b.header.requests_hash, /* with_prefix = */ true);
    }

    json["fullblock"]["transactions"] = b.transactions;
    for (size_t i{0}; i < json["fullblock"]["transactions"].size(); ++i) {
        auto& json_txn = json["fullblock"]["transactions"][i];
        json_txn["transactionIndex"] = to_quantity(b.receipts.at(i).tx_index);
        json_txn["blockHash"] = b.hash;
        json_txn["blockNumber"] = block_num;
        json_txn["gasPrice"] = to_quantity(b.transactions[i].effective_gas_price(b.header.base_fee_per_gas.value_or(0)));
        json_txn["input"] = "0x" + silkworm::to_hex(b.transactions[i].data.substr(0, 4));
    }

    json["fullblock"]["transactionsRoot"] = b.header.transactions_root;

    std::vector<evmc::bytes32> ommer_hashes;
    ommer_hashes.reserve(b.ommers.size());
    for (size_t i{0}; i < b.ommers.size(); ++i) {
        ommer_hashes.emplace(ommer_hashes.end(), b.ommers[i].hash());
        SILK_DEBUG << "ommer_hashes[" << i << "]: " << silkworm::to_hex({ommer_hashes[i].bytes, silkworm::kHashLength});
    }

    json["fullblock"]["uncles"] = ommer_hashes;
    json["receipts"] = b.receipts;
    for (size_t i{0}; i < json["receipts"].size(); ++i) {
        auto& json_txn = json["receipts"][i];
        json_txn["logs"] = nullptr;
        json_txn["logsBloom"] = nullptr;
        json_txn["effectiveGasPrice"] = to_quantity(b.transactions[i].effective_gas_price(b.header.base_fee_per_gas.value_or(0)));
    }
}

void to_json(nlohmann::json& json, const TransactionsWithReceipts& b) {
    json["firstPage"] = b.first_page;
    json["lastPage"] = b.last_page;
    json["txs"] = b.transactions;
    json["receipts"] = b.receipts;
    for (size_t i{0}; i < b.transactions.size(); ++i) {
        auto& json_txn = json["txs"][i];
        auto& json_receipt = json["receipts"][i];

        const auto hash = b.headers.at(i).hash();
        const auto gas_price = to_quantity(b.transactions[i].effective_gas_price(b.headers[i].base_fee_per_gas.value_or(0)));
        json_txn["blockHash"] = hash;
        json_txn["blockNumber"] = to_quantity(b.receipts.at(i).block_num);
        json_txn["gasPrice"] = gas_price;
        json_txn["transactionIndex"] = to_quantity(b.receipts.at(i).tx_index);

        json_receipt["blockHash"] = hash;
        json_receipt["blockNumber"] = to_quantity(b.receipts.at(i).block_num);
        json_receipt["timestamp"] = b.headers.at(i).timestamp;
        json_receipt["effectiveGasPrice"] = gas_price;
        json_receipt["transactionHash"] = json_txn["hash"];
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

void to_json(nlohmann::json& json, const Forks& forks) {
    json["genesis"] = forks.genesis_hash;
    json["heightForks"] = forks.block_nums;
    json["timeForks"] = forks.block_times;
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
        json.push_back(address_to_hex(address));
    }
}

nlohmann::json make_json_content(const nlohmann::json& request_json) {
    const nlohmann::json id = request_json.contains("id") ? request_json["id"] : nullptr;

    return {{"jsonrpc", kJsonVersion}, {"id", id}, {"result", nullptr}};
}

nlohmann::json make_json_content(const nlohmann::json& request_json, const nlohmann::json& result) {
    const nlohmann::json id = request_json.contains("id") ? request_json["id"] : nullptr;
    nlohmann::json json{{"jsonrpc", kJsonVersion}, {"id", id}, {"result", result}};
    return json;
}

nlohmann::json make_json_error(const nlohmann::json& request_json, int code, const std::string& message) {
    const nlohmann::json id = request_json.contains("id") ? request_json["id"] : nullptr;
    const Error error{code, message};
    return {{"jsonrpc", kJsonVersion}, {"id", id}, {"error", error}};
}

nlohmann::json make_json_error(const nlohmann::json& request_json, const RevertError& error) {
    const nlohmann::json id = request_json.contains("id") ? request_json["id"] : nullptr;
    return {{"jsonrpc", kJsonVersion}, {"id", id}, {"error", error}};
}

JsonRpcId make_jsonrpc_id(const nlohmann::json& request_json) {
    JsonRpcId json_rpc_id;
    if (request_json.contains("id")) {
        const auto& id = request_json["id"];
        if (id.is_number()) {
            json_rpc_id = id.get<std::uint32_t>();
        } else if (id.is_string()) {
            json_rpc_id = id.get<std::string>();
        } else {
            json_rpc_id = nullptr;
        }
    } else {
        json_rpc_id = nullptr;
    }
    return json_rpc_id;
}

}  // namespace silkworm::rpc
