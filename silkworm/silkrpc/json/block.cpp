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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/common/compatibility.hpp>
#include <silkworm/silkrpc/common/util.hpp>

#include "filter.hpp"
#include "types.hpp"

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
            "validatorindex", &T::validator_index,
            "address", &T::address,
            "amount", &T::amount);
    };
};

struct GlazeJsonTransactionItem {
    char from[addressSize];
    char gas[int64Size];
    char hash[hashSize];
    char input[dataSize];
    char nonce[int64Size];
    std::optional<std::string> chain_id;
    std::optional<std::string> max_fee_per_gas;
    std::optional<std::string> max_pri_fee_per_gas;
    char to[addressSize];
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
        using T = GlazeJsonTransactionItem;

        static constexpr auto value = glz::object(
            "from", &T::from,
            "gas", &T::gas,
            "hash", &T::hash,
            "input", &T::input,
            "nonce", &T::nonce,
            "to", &T::to,
            "value", &T::value,
            "chainId", &T::chain_id,
            "type", &T::type,
            "v", &T::v,
            "r", &T::r,
            "s", &T::s,
            "transactionIndex", &T::transaction_index,
            "blockHash", &T::block_hash,
            "blockNumber", &T::block_number,
            "maxPriorityFeePerGas", &T::max_pri_fee_per_gas,
            "maxFeePerGas", &T::max_fee_per_gas,
            "gasPrice", &T::gas_price);
    };
};

struct GlazeJsonBlockItem {
    char jsonrpc[jsonVersionSize] = "2.0";
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
    std::vector<std::string> transaction_hashes;
    std::vector<GlazeJsonTransactionItem> transactions_data;

    std::vector<std::string> ommers_hashes;
    std::vector<GlazeJsonWithdrawals> withdrawals;

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
    char jsonrpc[jsonVersionSize] = "2.0";
    uint32_t id;
    struct GlazeJsonBlockItem result;

    struct glaze {
        using T = GlazeJsonBlock;
        static constexpr auto value = glz::object(
            "jsonrpc", &T::jsonrpc,
            "id", &T::id,
            "result", &T::result);
    };
};

void make_glaze_json_content(GlazeJsonBlock& block_json_data, const Block& b) {
    for (std::size_t i{0}; i < b.block.withdrawals->size(); i++) {
        struct GlazeJsonWithdrawals item;
        to_quantity(std::span(item.index), (*(b.block.withdrawals))[i].index);
        to_quantity(std::span(item.amount), (*(b.block.withdrawals))[i].amount);
        to_quantity(std::span(item.validator_index), (*(b.block.withdrawals))[i].validator_index);
        to_hex(std::span(item.address), (*(b.block.withdrawals))[i].address.bytes);

        block_json_data.result.withdrawals.push_back(std::move(item));
    }
}

void make_glaze_json_content(std::string& reply, uint32_t id, const Block& b) {
    GlazeJsonBlock block_json_data{};

    block_json_data.id = id;
    to_quantity(std::span(block_json_data.result.block_number), b.block.header.number);
    to_hex(std::span(block_json_data.result.hash), b.hash.bytes);
    to_hex(std::span(block_json_data.result.parent_hash), b.block.header.parent_hash.bytes);
    to_hex(std::span(block_json_data.result.nonce), b.block.header.nonce);
    to_hex(std::span(block_json_data.result.sha3Uncles), b.block.header.ommers_hash.bytes);
    to_hex(std::span(block_json_data.result.transactions_root), b.block.header.transactions_root.bytes);
    to_hex(std::span(block_json_data.result.logs_bloom), b.block.header.logs_bloom);
    if (b.block.header.withdrawals_root) {
        block_json_data.result.withdrawals_root = "0x" + silkworm::to_hex(*(b.block.header.withdrawals_root));
    }
    to_hex(std::span(block_json_data.result.state_root), b.block.header.state_root.bytes);
    to_hex(std::span(block_json_data.result.receipts_root), b.block.header.receipts_root.bytes);
    to_hex(std::span(block_json_data.result.miner), b.block.header.beneficiary.bytes);

    to_quantity(std::span(block_json_data.result.size), b.get_block_size());
    to_quantity(std::span(block_json_data.result.gas_limit), b.block.header.gas_limit);
    to_quantity(std::span(block_json_data.result.gas_used), b.block.header.gas_used);
    to_quantity(std::span(block_json_data.result.difficulty), b.block.header.difficulty);
    to_quantity(std::span(block_json_data.result.total_difficulty), b.total_difficulty);
    to_hex(std::span(block_json_data.result.mix_hash), b.block.header.prev_randao.bytes);
    to_hex(std::span(block_json_data.result.extra_data), b.block.header.extra_data);

    if (b.block.header.base_fee_per_gas.has_value()) {
        block_json_data.result.base_fee_per_gas = to_quantity(b.block.header.base_fee_per_gas.value_or(0));
    }
    to_quantity(std::span(block_json_data.result.timestamp), b.block.header.timestamp);

#ifdef notdef
#endif
    if (b.full_tx) {
        for (std::size_t i{0}; i < b.block.transactions.size(); i++) {
            struct GlazeJsonTransactionItem item {};
            const silkworm::Transaction& transaction = b.block.transactions[i];

            if (!transaction.from) {
                (const_cast<silkworm::Transaction&>(transaction)).recover_sender();
            }
            if (transaction.from) {
                to_hex(std::span(item.from), transaction.from.value().bytes);
            }

            if (transaction.to) {
                to_hex(std::span(item.to), transaction.to.value().bytes);
            } else {
                to_hex(std::span(item.to), {});
            }
            to_quantity(std::span(item.gas), transaction.gas_limit);
            auto ethash_hash{hash_of_transaction(transaction)};
            auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
            to_hex(std::span(item.hash), bytes32_hash.bytes);
            to_hex(std::span(item.input), transaction.data);
            to_quantity(std::span(item.nonce), transaction.nonce);
            to_quantity(std::span(item.type), uint64_t(transaction.type));

            to_quantity(std::span(item.transaction_index), i);
            to_quantity(std::span(item.block_number), b.block.header.number);
            to_hex(std::span(item.block_hash), b.hash.bytes);
            to_quantity(std::span(item.gas_price), transaction.effective_gas_price(b.block.header.base_fee_per_gas.value_or(0)));
            if (transaction.type != silkworm::TransactionType::kLegacy) {
                item.chain_id = to_quantity(*transaction.chain_id);
                rpc::to_quantity(std::span(item.v), silkworm::endian::to_big_compact(transaction.v()));
                // json["accessList"] = transaction.access_list;  // EIP2930
                //  Erigon currently at 2.48.1 does not yet support yParity field
                if (not rpc::compatibility::is_erigon_json_api_compatibility_required()) {
                    // json["yParity"] = rpc::to_quantity(transaction.odd_y_parity);
                }
            } else if (transaction.chain_id) {
                item.chain_id = to_quantity(*transaction.chain_id);
                to_quantity(std::span(item.v), silkworm::endian::to_big_compact(transaction.v()));
            } else {
                rpc::to_quantity(std::span(item.v), silkworm::endian::to_big_compact(transaction.v()));
            }
            if (transaction.type == silkworm::TransactionType::kDynamicFee) {
                item.max_pri_fee_per_gas = rpc::to_quantity(transaction.max_priority_fee_per_gas);
                item.max_fee_per_gas = rpc::to_quantity(transaction.max_fee_per_gas);
            }
            to_quantity(std::span(item.value), transaction.value);
            rpc::to_quantity(std::span(item.r), silkworm::endian::to_big_compact(transaction.r));
            rpc::to_quantity(std::span(item.s), silkworm::endian::to_big_compact(transaction.s));
            block_json_data.result.transactions_data.push_back(item);
        }
    } else {
        block_json_data.result.transaction_hashes.reserve(b.block.transactions.size());
        for (std::size_t i{0}; i < b.block.transactions.size(); i++) {
            auto ethash_hash{hash_of_transaction(b.block.transactions[i])};
            auto bytes32_hash = silkworm::to_bytes32({ethash_hash.bytes, silkworm::kHashLength});
            block_json_data.result.transaction_hashes.push_back("0x" + silkworm::to_hex(bytes32_hash));
        }
    }
    block_json_data.result.ommers_hashes.reserve(b.block.ommers.size());
    for (std::size_t i{0}; i < b.block.ommers.size(); i++) {
        block_json_data.result.ommers_hashes.push_back("0x" + silkworm::to_hex(b.block.ommers[i].hash()));
    }

    if (b.block.withdrawals) {
        make_glaze_json_content(block_json_data, b);
    }

    glz::write_json(block_json_data, reply);
}

}  // namespace silkworm::rpc
