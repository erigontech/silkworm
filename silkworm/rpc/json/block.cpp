// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"

#include <silkworm/rpc/json/types.hpp>

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const Block& b) {
    auto& header = b.block_with_hash->block.header;
    const auto block_num = to_quantity(header.number);
    json["number"] = block_num;
    json["hash"] = b.block_with_hash->hash;
    json["parentHash"] = header.parent_hash;
    json["nonce"] = "0x" + silkworm::to_hex({header.nonce.data(), header.nonce.size()});
    json["sha3Uncles"] = header.ommers_hash;
    json["logsBloom"] = "0x" + silkworm::to_hex(full_view(header.logs_bloom));
    json["transactionsRoot"] = header.transactions_root;
    if (header.withdrawals_root) {
        json["withdrawalsRoot"] = *(header.withdrawals_root);
    }
    json["stateRoot"] = header.state_root;
    json["receiptsRoot"] = header.receipts_root;
    json["miner"] = header.beneficiary;
    json["difficulty"] = to_quantity(silkworm::endian::to_big_compact(header.difficulty));
    json["extraData"] = "0x" + silkworm::to_hex(header.extra_data);
    json["mixHash"] = header.prev_randao;
    json["size"] = to_quantity(b.get_block_size());
    json["gasLimit"] = to_quantity(header.gas_limit);
    json["gasUsed"] = to_quantity(header.gas_used);
    if (header.base_fee_per_gas.has_value()) {
        json["baseFeePerGas"] = to_quantity(header.base_fee_per_gas.value_or(0));
    }
    json["timestamp"] = to_quantity(header.timestamp);
    if (b.full_tx) {
        json["transactions"] = b.block_with_hash->block.transactions;
        for (size_t i{0}; i < json["transactions"].size(); ++i) {
            auto& json_txn = json["transactions"][i];
            json_txn["transactionIndex"] = to_quantity(i);
            json_txn["blockHash"] = b.block_with_hash->hash;
            json_txn["blockNumber"] = block_num;
            json_txn["gasPrice"] = to_quantity(b.block_with_hash->block.transactions[i].effective_gas_price(header.base_fee_per_gas.value_or(0)));
        }
    } else {
        std::vector<evmc::bytes32> transaction_hashes;
        transaction_hashes.reserve(b.block_with_hash->block.transactions.size());
        for (size_t i{0}; i < b.block_with_hash->block.transactions.size(); ++i) {
            transaction_hashes.emplace(transaction_hashes.end(), b.block_with_hash->block.transactions[i].hash());
            SILK_DEBUG << "transaction_hashes[" << i << "]: " << silkworm::to_hex({transaction_hashes[i].bytes, silkworm::kHashLength});
        }
        json["transactions"] = transaction_hashes;
    }
    std::vector<evmc::bytes32> ommer_hashes;
    ommer_hashes.reserve(b.block_with_hash->block.ommers.size());
    for (size_t i{0}; i < b.block_with_hash->block.ommers.size(); ++i) {
        ommer_hashes.emplace(ommer_hashes.end(), b.block_with_hash->block.ommers[i].hash());
        SILK_DEBUG << "ommer_hashes[" << i << "]: " << silkworm::to_hex({ommer_hashes[i].bytes, silkworm::kHashLength});
    }
    json["uncles"] = ommer_hashes;
    if (b.block_with_hash->block.withdrawals) {
        json["withdrawals"] = *(b.block_with_hash->block.withdrawals);
    }
}

struct GlazeJsonBlock {
    char block_num[kInt64HexSize];
    char hash[kHashHexSize];
    char parent_hash[kHashHexSize];
    char nonce[kInt64HexSize];
    char sha3_uncles[kHashHexSize];
    char logs_bloom[kBloomSize];
    char transactions_root[kHashHexSize];
    char state_root[kHashHexSize];
    char receipts_root[kHashHexSize];
    char miner[kAddressHexSize];
    char size[kInt64HexSize];
    char gas_limit[kInt64HexSize];
    char gas_used[kInt64HexSize];
    char timestamp[kInt64HexSize];
    char difficulty[kInt256HexSize];
    char mix_hash[kHashHexSize];
    char extra_data[kDataSize];

    std::vector<std::string> ommers_hashes;
    std::optional<std::string> base_fee_per_gas;
    std::optional<std::vector<std::string>> transaction_hashes;
    std::optional<std::vector<GlazeJsonTransaction>> transactions;
    std::optional<std::vector<GlazeJsonWithdrawals>> withdrawals;
    std::optional<std::string> withdrawals_root;
    std::optional<std::string> blob_gas_used;
    std::optional<std::string> excess_blob_gas;
    std::optional<std::string> parent_beacon_block_root;
    std::optional<std::string> requests_hash;

    struct glaze {
        using T = GlazeJsonBlock;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "number", &T::block_num,
            "hash", &T::hash,
            "parentHash", &T::parent_hash,
            "nonce", &T::nonce,
            "sha3Uncles", &T::sha3_uncles,
            "logsBloom", &T::logs_bloom,
            "transactionsRoot", &T::transactions_root,
            "withdrawalsRoot", &T::withdrawals_root,
            "stateRoot", &T::state_root,
            "receiptsRoot", &T::receipts_root,
            "miner", &T::miner,
            "size", &T::size,
            "gasLimit", &T::gas_limit,
            "blobGasUsed", &T::blob_gas_used,
            "excessBlobGas", &T::excess_blob_gas,
            "parentBeaconBlockRoot", &T::parent_beacon_block_root,
            "timestamp", &T::timestamp,
            "difficulty", &T::difficulty,
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
    JsonRpcId id;
    GlazeJsonBlock result;

    struct glaze {
        using T = GlazeJsonBlockReply;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

struct GlazeJsonNullBlockReply {
    std::string_view jsonrpc = kJsonVersion;
    JsonRpcId id;
    std::monostate result;

    struct glaze {
        using T = GlazeJsonNullBlockReply;
        // NOLINTNEXTLINE(readability-identifier-naming)
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_null_content(const nlohmann::json& request_json, std::string& json_reply) {
    GlazeJsonNullBlockReply block_json_data{};
    block_json_data.id = make_jsonrpc_id(request_json);

    glz::write<glz::opts{.skip_null_members = false}>(block_json_data, json_reply);
}

void make_glaze_json_content(const nlohmann::json& request_json, const Block& b, std::string& json_reply) {
    auto& block = b.block_with_hash->block;
    GlazeJsonBlockReply block_json_data{};
    auto& header = block.header;
    auto& result = block_json_data.result;

    block_json_data.id = make_jsonrpc_id(request_json);

    to_quantity(std::span(result.block_num), header.number);
    to_hex(std::span(result.hash), b.block_with_hash->hash.bytes);
    to_hex(std::span(result.parent_hash), header.parent_hash.bytes);
    to_hex(std::span(result.nonce), header.nonce);
    to_hex(std::span(result.sha3_uncles), header.ommers_hash.bytes);
    to_hex(std::span(result.transactions_root), header.transactions_root.bytes);
    to_hex(std::span(result.logs_bloom), header.logs_bloom);
    if (header.withdrawals_root) {
        result.withdrawals_root = std::make_optional("0x" + silkworm::to_hex(*(header.withdrawals_root)));
    }
    if (header.blob_gas_used) {
        result.blob_gas_used = std::make_optional(to_quantity(*(header.blob_gas_used)));
    }
    if (header.excess_blob_gas) {
        result.excess_blob_gas = std::make_optional(to_quantity(*(header.excess_blob_gas)));
    }
    if (header.parent_beacon_block_root) {
        result.parent_beacon_block_root = std::make_optional("0x" + silkworm::to_hex(*(header.parent_beacon_block_root)));
    }
    if (header.requests_hash) {
        result.requests_hash = std::make_optional("0x" + silkworm::to_hex(*(header.requests_hash)));
    }
    to_hex(std::span(result.state_root), header.state_root.bytes);
    to_hex(std::span(result.receipts_root), header.receipts_root.bytes);
    to_hex(std::span(result.miner), header.beneficiary.bytes);

    to_quantity(std::span(result.size), b.get_block_size());
    to_quantity(std::span(result.gas_limit), header.gas_limit);
    to_quantity(std::span(result.gas_used), header.gas_used);
    to_quantity(std::span(result.difficulty), header.difficulty);

    to_hex(std::span(result.mix_hash), header.prev_randao.bytes);
    to_hex(std::span(result.extra_data), header.extra_data);

    if (header.base_fee_per_gas.has_value()) {
        result.base_fee_per_gas = std::make_optional(to_quantity(header.base_fee_per_gas.value_or(0)));
    }
    to_quantity(std::span(result.timestamp), header.timestamp);

    if (b.full_tx) {
        std::vector<GlazeJsonTransaction> transaction_data_list;
        transaction_data_list.reserve(block.transactions.size());
        for (size_t i{0}; i < block.transactions.size(); ++i) {
            const silkworm::Transaction& transaction = block.transactions[i];
            GlazeJsonTransaction item{};
            to_quantity(std::span(item.transaction_index), i);
            to_quantity(std::span(item.block_num), header.number);
            to_hex(std::span(item.block_hash), b.block_with_hash->hash.bytes);
            to_quantity(std::span(item.gas_price), transaction.effective_gas_price(header.base_fee_per_gas.value_or(0)));
            make_glaze_json_transaction(transaction, item);
            transaction_data_list.push_back(std::move(item));
        }
        result.transactions = make_optional(std::move(transaction_data_list));
    } else {
        std::vector<std::string> transaction_hashes;
        transaction_hashes.reserve(block.transactions.size());
        for (const auto& transaction : block.transactions) {
            transaction_hashes.push_back("0x" + silkworm::to_hex(transaction.hash()));
        }
        result.transaction_hashes = std::make_optional(std::move(transaction_hashes));
    }
    result.ommers_hashes.reserve(block.ommers.size());
    for (const auto& ommer : block.ommers) {
        result.ommers_hashes.push_back("0x" + silkworm::to_hex(ommer.hash()));
    }

    if (block.withdrawals) {
        result.withdrawals = make_glaze_json_withdrawals(block);
    }
    glz::write_json(block_json_data, json_reply);
}

}  // namespace silkworm::rpc
