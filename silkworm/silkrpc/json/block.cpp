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

struct GlazeJsonWithdrawals {
    char index[int64Size];
    char validator_index[int64Size];
    char address[addressSize];
    char amount[int64Size];

    struct glaze {
        using T = GlazeJsonWithdrawals;
        static constexpr auto value = glz::object(
            "index", &T::index,
            "validatorIndex", &T::validator_index,
            "address", &T::address,
            "amount", &T::amount);
    };
};

struct GlazeJsonAccessList {
    char address[addressSize];
    std::vector<std::string> storage_keys;
    struct glaze {
        using T = GlazeJsonAccessList;
        static constexpr auto value = glz::object(
            "address", &T::address,
            "storageKeys", &T::storage_keys);
    };
};

struct GlazeJsonTransaction {
    char from[addressSize];
    char gas[int64Size];
    char hash[hashSize];
    std::string input;
    char nonce[int64Size];
    std::optional<std::string> yparity;
    std::optional<std::string> chain_id;
    std::optional<std::string> max_fee_per_gas;
    std::optional<std::string> max_pri_fee_per_gas;
    std::optional<std::vector<GlazeJsonAccessList>> access_list;
    std::optional<std::string> to;
    std::optional<std::monostate> nullto;
    char value[int64Size];
    char type[int64Size];
    char v[hashSize];
    char r[hashSize];
    char s[hashSize];

    char transaction_index[int64Size];
    char block_hash[hashSize];
    char block_number[int64Size];
    char gas_price[int64Size];

    struct glaze {
        using T = GlazeJsonTransaction;

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
            "accesslist", &T::access_list,
            "to", &T::to,
            "to", &T::nullto,
            "value", &T::value,
            "type", &T::type,
            "v", &T::v,
            "r", &T::r,
            "s", &T::s,
            "transactionIndex", &T::transaction_index,
            "blockHash", &T::block_hash,
            "blockNumber", &T::block_number,
            "gasPrice", &T::gas_price);
    };
};

struct GlazeJsonBlockItem {
    char jsonrpc[jsonVersionSize] = jsonVersion;
    uint32_t id;
    char block_number[int64Size];
    char hash[hashSize];
    char parent_hash[hashSize];
    char nonce[int64Size];
    char sha3Uncles[hashSize];
    char logs_bloom[bloomSize];
    char transactions_root[hashSize];
    std::optional<std::string> withdrawals_root;
    char state_root[hashSize];
    char receipts_root[hashSize];
    char miner[addressSize];
    char size[int64Size];
    char gas_limit[int64Size];
    char gas_used[int64Size];
    char timestamp[int64Size];
    char difficulty[int64Size];
    char total_difficulty[int64Size];
    char mix_hash[hashSize];
    char extra_data[dataSize];
    std::optional<std::string> base_fee_per_gas;
    std::optional<std::vector<std::string>> transaction_hashes;
    std::optional<std::vector<GlazeJsonTransaction>> transactions_data;

    std::vector<std::string> ommers_hashes;
    std::optional<std::vector<GlazeJsonWithdrawals>> withdrawals;

    struct glaze {
        using T = GlazeJsonBlockItem;
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
            "transactions", &T::transactions_data,
            "uncles", &T::ommers_hashes,
            "withdrawals", &T::withdrawals);
    };
};

struct GlazeJsonBlock {
    char jsonrpc[jsonVersionSize] = jsonVersion;
    uint32_t id;
    GlazeJsonBlockItem result;

    struct glaze {
        using T = GlazeJsonBlock;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

struct GlazeJsonNullBlock {
    char jsonrpc[jsonVersionSize] = jsonVersion;
    uint32_t id;
    std::monostate result;

    struct glaze {
        using T = GlazeJsonNullBlock;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_withdrawls_content(GlazeJsonBlock& block_json_data, const BlockBody& block) {
    std::vector<GlazeJsonWithdrawals> withdrawals;
    withdrawals.reserve(block.withdrawals->size());
    for (std::size_t i{0}; i < block.withdrawals->size(); i++) {
        GlazeJsonWithdrawals item;
        to_quantity(std::span(item.index), (*(block.withdrawals))[i].index);
        to_quantity(std::span(item.amount), (*(block.withdrawals))[i].amount);
        to_quantity(std::span(item.validator_index), (*(block.withdrawals))[i].validator_index);
        to_hex(std::span(item.address), (*(block.withdrawals))[i].address.bytes);
        withdrawals.push_back(std::move(item));
    }
    block_json_data.result.withdrawals = make_optional(std::move(withdrawals));
}

void make_glaze_json_null_content(std::string& reply, uint32_t id) {
    GlazeJsonNullBlock block_json_data{};
    block_json_data.id = id;

    glz::write<glz::opts{.skip_null_members = false}>(block_json_data, reply);
}

void make_glaze_json_transaction_content(GlazeJsonTransaction& item, const silkworm::Transaction& transaction) {
    if (!transaction.from) {
        (const_cast<silkworm::Transaction&>(transaction)).recover_sender();
    }
    if (transaction.from) {
        to_hex(std::span(item.from), transaction.from.value().bytes);
    }

    if (transaction.to) {
        item.to = std::make_optional("0x" + silkworm::to_hex(transaction.to.value().bytes));
    } else {
        std::monostate null_value{};
        item.nullto = std::make_optional(std::move(null_value));
    }
    to_quantity(std::span(item.gas), transaction.gas_limit);
    auto ethash_hash{hash_of_transaction(transaction)};
    auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
    to_hex(std::span(item.hash), bytes32_hash.bytes);
    item.input.reserve(transaction.data.size() * 2 + 3);
    item.input = "0x" + silkworm::to_hex(transaction.data);
    to_quantity(std::span(item.nonce), transaction.nonce);
    to_quantity(std::span(item.type), uint64_t(transaction.type));

    if (transaction.type != silkworm::TransactionType::kLegacy) {
        item.chain_id = std::make_optional(to_quantity(*transaction.chain_id));
        to_quantity(std::span(item.v), uint64_t(transaction.odd_y_parity));

        std::vector<GlazeJsonAccessList> glaze_access_list;
        glaze_access_list.reserve(transaction.access_list.size());
        for (const auto& access_list : transaction.access_list) {
            GlazeJsonAccessList access_list_item;
            to_hex(std::span(access_list_item.address), access_list.account.bytes);
            for (const auto& storage_key : access_list.storage_keys) {
                auto key_hash = silkworm::to_bytes32({storage_key.bytes, silkworm::kHashLength});
                access_list_item.storage_keys.push_back(silkworm::to_hex(key_hash.bytes));
            }
            glaze_access_list.push_back(std::move(access_list_item));
        }
        item.access_list = std::make_optional(std::move(glaze_access_list));

        //  Erigon currently at 2.48.1 does not yet support yParity field
        if (not rpc::compatibility::is_erigon_json_api_compatibility_required()) {
            item.yparity = std::make_optional(rpc::to_quantity(transaction.odd_y_parity));
        }
    } else if (transaction.chain_id) {
        item.chain_id = std::make_optional(to_quantity(*transaction.chain_id));
        to_quantity(std::span(item.v), silkworm::endian::to_big_compact(transaction.v()));
    } else {
        rpc::to_quantity(std::span(item.v), silkworm::endian::to_big_compact(transaction.v()));
    }
    if (transaction.type == silkworm::TransactionType::kDynamicFee) {
        item.max_pri_fee_per_gas = std::make_optional(rpc::to_quantity(transaction.max_priority_fee_per_gas));
        item.max_fee_per_gas = std::make_optional(rpc::to_quantity(transaction.max_fee_per_gas));
    }
    to_quantity(std::span(item.value), transaction.value);
    to_quantity(std::span(item.r), silkworm::endian::to_big_compact(transaction.r));
    to_quantity(std::span(item.s), silkworm::endian::to_big_compact(transaction.s));
}

void make_glaze_json_content(std::string& reply, uint32_t id, const Block& b) {
    GlazeJsonBlock block_json_data{};
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
            make_glaze_json_transaction_content(item, transaction);
            transaction_data_list.push_back(std::move(item));
        }
        result.transactions_data = make_optional(std::move(transaction_data_list));
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
        make_glaze_json_withdrawls_content(block_json_data, block);
    }
    glz::write_json(block_json_data, reply);
}

}  // namespace silkworm::rpc
