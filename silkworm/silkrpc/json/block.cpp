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

#include "block.hpp"

#include <silkworm/silkrpc/common/compatibility.hpp>
#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Block& b) {
    const auto block_number = to_quantity(b.block.header.number);
    json["number"] = block_number;
    json["hash"] = b.hash;
    json["parentHash"] = b.block.header.parent_hash;
    json["nonce"] = "0x" + silkworm::to_hex({b.block.header.nonce.data(), b.block.header.nonce.size()});
    json["sha3Uncles"] = b.block.header.ommers_hash;
    json["logsBloom"] = "0x" + silkworm::to_hex(full_view(b.block.header.logs_bloom));
    json["transactionsRoot"] = b.block.header.transactions_root;
    if (b.block.header.withdrawals_root) {
        json["withdrawalsRoot"] = *(b.block.header.withdrawals_root);
    }
    json["stateRoot"] = b.block.header.state_root;
    json["receiptsRoot"] = b.block.header.receipts_root;
    json["miner"] = b.block.header.beneficiary;
    json["difficulty"] = to_quantity(silkworm::endian::to_big_compact(b.block.header.difficulty));
    json["totalDifficulty"] = to_quantity(silkworm::endian::to_big_compact(b.total_difficulty));
    json["extraData"] = "0x" + silkworm::to_hex(b.block.header.extra_data);
    json["mixHash"] = b.block.header.prev_randao;
    json["size"] = to_quantity(b.get_block_size());
    json["gasLimit"] = to_quantity(b.block.header.gas_limit);
    json["gasUsed"] = to_quantity(b.block.header.gas_used);
    if (b.block.header.base_fee_per_gas.has_value()) {
        json["baseFeePerGas"] = to_quantity(b.block.header.base_fee_per_gas.value_or(0));
    }
    json["timestamp"] = to_quantity(b.block.header.timestamp);
    if (b.full_tx) {
        json["transactions"] = b.block.transactions;
        for (std::size_t i{0}; i < json["transactions"].size(); i++) {
            auto& json_txn = json["transactions"][i];
            json_txn["transactionIndex"] = to_quantity(i);
            json_txn["blockHash"] = b.hash;
            json_txn["blockNumber"] = block_number;
            json_txn["gasPrice"] = to_quantity(b.block.transactions[i].effective_gas_price(b.block.header.base_fee_per_gas.value_or(0)));
        }
    } else {
        std::vector<evmc::bytes32> transaction_hashes;
        transaction_hashes.reserve(b.block.transactions.size());
        for (std::size_t i{0}; i < b.block.transactions.size(); i++) {
            auto ethash_hash{hash_of_transaction(b.block.transactions[i])};
            auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
            transaction_hashes.emplace(transaction_hashes.end(), bytes32_hash);
            SILK_DEBUG << "transaction_hashes[" << i << "]: " << silkworm::to_hex({transaction_hashes[i].bytes, silkworm::kHashLength});
        }
        json["transactions"] = transaction_hashes;
    }
    std::vector<evmc::bytes32> ommer_hashes;
    ommer_hashes.reserve(b.block.ommers.size());
    for (std::size_t i{0}; i < b.block.ommers.size(); i++) {
        ommer_hashes.emplace(ommer_hashes.end(), b.block.ommers[i].hash());
        SILK_DEBUG << "ommer_hashes[" << i << "]: " << silkworm::to_hex({ommer_hashes[i].bytes, silkworm::kHashLength});
    }
    json["uncles"] = ommer_hashes;
    if (b.block.withdrawals) {
        json["withdrawals"] = *(b.block.withdrawals);
    }
}

struct GlazeJsonBlock {
    char block_number[kInt64HexSize];
    char hash[kHashHexSize];
    char parent_hash[kHashHexSize];
    char nonce[kInt64HexSize];
    char sha3Uncles[kHashHexSize];
    char logs_bloom[kBloomSize];
    char transactions_root[kHashHexSize];
    char state_root[kHashHexSize];
    char receipts_root[kHashHexSize];
    char miner[kAddressHexSize];
    char size[kInt64HexSize];
    char gas_limit[kInt64HexSize];
    char gas_used[kInt64HexSize];
    char timestamp[kInt64HexSize];
    char difficulty[kInt64HexSize];
    char total_difficulty[kInt64HexSize];
    char mix_hash[kHashHexSize];
    char extra_data[kDataSize];

    std::vector<std::string> ommers_hashes;
    std::optional<std::string> base_fee_per_gas;
    std::optional<std::vector<std::string>> transaction_hashes;
    std::optional<std::vector<GlazeJsonTransaction>> transactions;
    std::optional<std::vector<GlazeJsonWithdrawals>> withdrawals;
    std::optional<std::string> withdrawals_root;

    struct glaze {
        using T = GlazeJsonBlock;
        static constexpr auto value = glz::object(
            "number", &T::block_number,
            "hash", &T::hash,
            "parentHash", &T::parent_hash,
            "nonce", &T::nonce,
            "sha3Uncles", &T::sha3Uncles,
            "logsBloom", &T::logs_bloom,
            "transactionsRoot", &T::transactions_root,
            "withdrawalsRoot", &T::withdrawals_root,
            "stateRoot", &T::state_root,
            "receiptsRoot", &T::receipts_root,
            "miner", &T::miner,
            "size", &T::size,
            "gasLimit", &T::gas_limit,
            "timestamp", &T::timestamp,
            "difficulty", &T::difficulty,
            "totalDifficulty", &T::total_difficulty,
            "mixHash", &T::mix_hash,
            "extraData", &T::extra_data,
            "baseFeePerGas", &T::base_fee_per_gas,
            "gasUsed", &T::gas_used,
            "transactions", &T::transaction_hashes,
            "transactions", &T::transactions,
            "uncles", &T::ommers_hashes,
            "withdrawals", &T::withdrawals);
    };
};

struct GlazeJsonBlockReply {
    std::string_view jsonrpc = kJsonVersion;
    uint32_t id;
    GlazeJsonBlock result;

    struct glaze {
        using T = GlazeJsonBlockReply;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

struct GlazeJsonNullBlockReply {
    std::string_view jsonrpc = kJsonVersion;
    uint32_t id;
    std::monostate result;

    struct glaze {
        using T = GlazeJsonNullBlockReply;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_null_content(uint32_t id, std::string& json_reply) {
    GlazeJsonNullBlockReply block_json_data{};
    block_json_data.id = id;

    glz::write<glz::opts{.skip_null_members = false}>(block_json_data, json_reply);
}

void make_glaze_json_content(uint32_t id, const Block& b, std::string& json_reply) {
    GlazeJsonBlockReply block_json_data{};
    auto& block = b.block;
    auto& header = block.header;
    auto& result = block_json_data.result;

    block_json_data.id = id;
    to_quantity(std::span(result.block_number), header.number);
    to_hex(std::span(result.hash), b.hash.bytes);
    to_hex(std::span(result.parent_hash), header.parent_hash.bytes);
    to_hex(std::span(result.nonce), header.nonce);
    to_hex(std::span(result.sha3Uncles), header.ommers_hash.bytes);
    to_hex(std::span(result.transactions_root), header.transactions_root.bytes);
    to_hex(std::span(result.logs_bloom), header.logs_bloom);
    if (header.withdrawals_root) {
        result.withdrawals_root = std::make_optional("0x" + silkworm::to_hex(*(header.withdrawals_root)));
    }
    to_hex(std::span(result.state_root), header.state_root.bytes);
    to_hex(std::span(result.receipts_root), header.receipts_root.bytes);
    to_hex(std::span(result.miner), header.beneficiary.bytes);

    to_quantity(std::span(result.size), b.get_block_size());
    to_quantity(std::span(result.gas_limit), header.gas_limit);
    to_quantity(std::span(result.gas_used), header.gas_used);
    to_quantity(std::span(result.difficulty), header.difficulty);
    to_quantity(std::span(result.total_difficulty), b.total_difficulty);
    to_hex(std::span(result.mix_hash), header.prev_randao.bytes);
    to_hex(std::span(result.extra_data), header.extra_data);

    if (header.base_fee_per_gas.has_value()) {
        result.base_fee_per_gas = std::make_optional(to_quantity(header.base_fee_per_gas.value_or(0)));
    }
    to_quantity(std::span(result.timestamp), header.timestamp);

    if (b.full_tx) {
        std::vector<GlazeJsonTransaction> transaction_data_list;
        transaction_data_list.reserve(block.transactions.size());
        for (std::size_t i{0}; i < block.transactions.size(); i++) {
            const silkworm::Transaction& transaction = block.transactions[i];
            GlazeJsonTransaction item{};
            to_quantity(std::span(item.transaction_index), i);
            to_quantity(std::span(item.block_number), header.number);
            to_hex(std::span(item.block_hash), b.hash.bytes);
            to_quantity(std::span(item.gas_price), transaction.effective_gas_price(header.base_fee_per_gas.value_or(0)));
            make_glaze_json_transaction(transaction, item);
            transaction_data_list.push_back(std::move(item));
        }
        result.transactions = make_optional(std::move(transaction_data_list));
    } else {
        std::vector<std::string> transaction_hashes;
        transaction_hashes.reserve(block.transactions.size());
        for (const auto& transaction : block.transactions) {
            auto ethash_hash{hash_of_transaction(transaction)};
            auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
            transaction_hashes.push_back("0x" + silkworm::to_hex(bytes32_hash));
        }
        result.transaction_hashes = std::make_optional(std::move(transaction_hashes));
    }
    result.ommers_hashes.reserve(block.ommers.size());
    for (const auto& ommer : block.ommers) {
        result.ommers_hashes.push_back("0x" + silkworm::to_hex(ommer.hash()));
    }

    if (block.withdrawals) {
        result.withdrawals = std::move(make_glaze_json_withdrawals(block));
    }
    glz::write_json(block_json_data, json_reply);
}

}  // namespace silkworm::rpc
