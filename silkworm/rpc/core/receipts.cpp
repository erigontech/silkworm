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

#include "receipts.hpp"

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/state/receipts_domain.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/execution/state_factory.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/async_task.hpp>
#include <silkworm/rpc/core/evm_executor.hpp>
#include <silkworm/rpc/ethdb/cbor.hpp>
#include <silkworm/rpc/ethdb/walk.hpp>
#include <silkworm/rpc/types/receipt.hpp>

namespace silkworm::rpc::core {

using ethdb::walk;

static constexpr int kGasPerBlob = 0x20000;
const Bytes kCumulativeGasUsedKey{static_cast<uint8_t>(db::state::ReceiptsDomainKey::kCumulativeBlobGasUsedInBlockKey)};
const Bytes kFirstLogIndexKey{static_cast<uint8_t>(db::state::ReceiptsDomainKey::kFirstLogIndexKey)};

Task<Receipts> get_receipts(db::kv::api::Transaction& tx,
                            const silkworm::BlockWithHash& block_with_hash,
                            const db::chain::ChainStorage& chain_storage,
                            WorkerPool& workers,
                            bool extended_receipt_info) {
    if (block_with_hash.block.transactions.empty()) {
        co_return Receipts{};
    }

    const evmc::bytes32 block_hash = block_with_hash.hash;
    const BlockNum block_num = block_with_hash.block.header.number;

    // Try to read receipts from storage, if not present regenerate them
    auto raw_receipts = co_await read_receipts(tx, block_num);
    if (!raw_receipts || raw_receipts->empty()) {
        raw_receipts = co_await generate_receipts(tx, block_with_hash.block, chain_storage, workers);
        if (!raw_receipts || raw_receipts->empty()) {
            co_return Receipts{};
        }
    }
    auto& receipts = *raw_receipts;

    const auto& transactions = block_with_hash.block.transactions;
    SILK_DEBUG << "#transactions=" << block_with_hash.block.transactions.size() << " #receipts=" << receipts.size();
    if (transactions.size() != receipts.size()) {
        throw std::runtime_error{"#transactions and #receipts do not match in get_receipts"};
    }

    if (!extended_receipt_info) {
        co_return receipts;
    }

    // Add derived fields to the receipts
    const auto& header = block_with_hash.block.header;

    uint32_t log_index{0};
    for (size_t i{0}; i < receipts.size(); ++i) {
        // The tx hash can be calculated by the tx content itself
        auto tx_hash{transactions[i].hash()};
        receipts[i].tx_hash = to_bytes32(tx_hash.bytes);
        receipts[i].tx_index = static_cast<uint32_t>(i);

        receipts[i].block_hash = block_hash;
        receipts[i].block_num = block_num;

        if (!transactions[i].blob_versioned_hashes.empty()) {
            receipts[i].blob_gas_used = kGasPerBlob * transactions[i].blob_versioned_hashes.size();
            if (header.excess_blob_gas) {
                receipts[i].blob_gas_price = header.blob_gas_price();
            }
        }

        // When tx receiver is not set, create a contract with address depending on tx sender and its nonce
        if (!transactions[i].to.has_value()) {
            receipts[i].contract_address = create_address(*transactions[i].sender(), transactions[i].nonce);
        }

        // The gas used can be calculated by the previous receipt
        if (i == 0) {
            receipts[i].gas_used = receipts[i].cumulative_gas_used;
        } else {
            receipts[i].gas_used = receipts[i].cumulative_gas_used - receipts[i - 1].cumulative_gas_used;
        }

        receipts[i].from = transactions[i].sender();
        receipts[i].to = transactions[i].to;
        receipts[i].type = transactions[i].type;

        // The derived fields of receipt are taken from block and transaction
        for (size_t j{0}; j < receipts[i].logs.size(); ++j) {
            receipts[i].logs[j].block_num = block_num;
            receipts[i].logs[j].block_hash = block_hash;
            receipts[i].logs[j].tx_hash = receipts[i].tx_hash;
            receipts[i].logs[j].tx_index = static_cast<uint32_t>(i);
            receipts[i].logs[j].index = log_index++;
            receipts[i].logs[j].removed = false;
        }
    }

    co_return receipts;
}

Task<std::optional<Receipts>> read_receipts(db::kv::api::Transaction& tx, BlockNum block_num) {
    const auto block_key = db::block_key(block_num);
    const auto data = co_await tx.get_one(db::table::kBlockReceiptsName, block_key);
    SILK_TRACE << "read_receipts data: " << silkworm::to_hex(data);
    if (data.empty()) {
        co_return std::nullopt;
    }

    Receipts receipts{};
    const bool decoding_ok{cbor_decode(data, receipts)};
    if (!decoding_ok) {
        throw std::runtime_error("cannot decode raw receipts in block: " + std::to_string(block_num));
    }
    SILK_TRACE << "#receipts: " << receipts.size();
    if (receipts.empty()) {
        co_return receipts;
    }

    auto log_key = db::log_key(block_num, 0);
    SILK_DEBUG << "log_key: " << silkworm::to_hex(log_key);
    auto walker = [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
        if (k.size() != sizeof(uint64_t) + sizeof(uint32_t)) {
            return false;
        }
        auto tx_id = endian::load_big_u32(&k[sizeof(uint64_t)]);
        const bool decode_ok{cbor_decode(v, receipts[tx_id].logs)};
        if (!decode_ok) {
            SILK_WARN << "cannot decode logs for receipt: " << tx_id << " in block: " << block_num;
            return false;
        }
        receipts[tx_id].bloom = bloom_from_logs(receipts[tx_id].logs);
        SILK_DEBUG << "#receipts[" << tx_id << "].logs: " << receipts[tx_id].logs.size();
        return true;
    };
    co_await walk(tx, db::table::kLogsName, log_key, 8 * CHAR_BIT, walker);

    co_return receipts;
}

Task<std::optional<Receipts>> generate_receipts(db::kv::api::Transaction& tx,
                                                const silkworm::Block& block,
                                                const db::chain::ChainStorage& chain_storage,
                                                WorkerPool& workers) {
    auto block_num = block.header.number;
    const auto& transactions = block.transactions;

    SILK_TRACE << "generate_receipts: block_num: " << std::dec << block_num << " #txns: " << transactions.size();

    const auto chain_config = co_await chain_storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;

    execution::StateFactory state_factory{tx};
    const auto txn_id = co_await tx.user_txn_id_at(block_num);

    const auto receipts = co_await async_task(workers.executor(), [&]() -> Receipts {
        auto state = state_factory.create_state(current_executor, chain_storage, txn_id);

        EVMExecutor executor{block, chain_config, workers, state};

        Receipts rpc_receipts;
        uint64_t cumulative_gas_used{0};

        for (size_t index = 0; index < transactions.size(); ++index) {
            Receipt receipt;

            const silkworm::Transaction& transaction{block.transactions[index]};
            auto result = executor.call_with_receipt(transaction, receipt, {}, /*refund=*/true, /*gas_bailout=*/false);

            cumulative_gas_used += receipt.gas_used;
            receipt.cumulative_gas_used = cumulative_gas_used;
            rpc_receipts.push_back(receipt);

            executor.reset();
        }
        return rpc_receipts;
    });

    co_return receipts;
}

Task<std::optional<Receipt>> get_receipt(db::kv::api::Transaction& tx,
                                         const silkworm::Block& block,
                                         TxnId txn_id,
                                         uint32_t tx_index,
                                         const silkworm::Transaction& transaction,
                                         const db::chain::ChainStorage& chain_storage,
                                         WorkerPool& workers) {
    using Word = snapshots::Decoder::Word;

    const auto chain_config = co_await chain_storage.read_chain_config();
    auto current_executor = co_await boost::asio::this_coro::executor;

    execution::StateFactory state_factory{tx};

    auto new_receipt = co_await async_task(workers.executor(), [&]() -> Receipt {
        auto state = state_factory.create_state(current_executor, chain_storage, txn_id);

        EVMExecutor executor{block, chain_config, workers, state};

        Receipt receipt;

        auto result = executor.call_with_receipt(transaction, receipt, {}, /*refund=*/true, /*gas_bailout=*/false);

        return receipt;
    });

    txn_id++;  // query db on next txn

    db::kv::api::GetAsOfRequest query_cumulative_gas{
        .table = db::table::kReceiptDomain,
        .key = kCumulativeGasUsedKey,
        .timestamp = static_cast<db::kv::api::Timestamp>(txn_id),
    };
    auto result = co_await tx.get_as_of(std::move(query_cumulative_gas));
    if (!result.success) {
        co_return std::nullopt;
    }

    db::state::VarintSnapshotsDecoder varint;
    Word value1{std::move(result.value)};
    varint.decode_word(value1);
    auto first_cumulative_gas_used_in_tx = varint.value;

    db::kv::api::GetAsOfRequest query_first_log_index{
        .table = db::table::kReceiptDomain,
        .key = kFirstLogIndexKey,
        .timestamp = static_cast<db::kv::api::Timestamp>(txn_id),
    };
    result = co_await tx.get_as_of(std::move(query_first_log_index));
    if (!result.success) {
        co_return std::nullopt;
    }

    Word value2{std::move(result.value)};
    varint.decode_word(value2);
    auto first_log_index = static_cast<uint32_t>(varint.value);

    new_receipt.cumulative_gas_used = first_cumulative_gas_used_in_tx;
    new_receipt.from = transaction.sender();
    new_receipt.to = transaction.to;
    new_receipt.type = transaction.type;

    for (auto& curr_log : new_receipt.logs) {
        curr_log.block_num = block.header.number;
        curr_log.block_hash = block.header.hash();
        curr_log.tx_hash = transaction.hash();
        curr_log.tx_index = tx_index;
        curr_log.index = first_log_index++;
        curr_log.removed = false;
    }

    co_return new_receipt;
}

}  // namespace silkworm::rpc::core
