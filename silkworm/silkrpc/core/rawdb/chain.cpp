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

#include "chain.hpp"

#include <string>
#include <utility>

#include <boost/endian/conversion.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/ethdb/cbor.hpp>
#include <silkworm/silkrpc/json/types.hpp>
#include <silkworm/silkrpc/types/receipt.hpp>

namespace silkworm::rpc::core::rawdb {

boost::asio::awaitable<uint64_t> read_header_number(const DatabaseReader& reader, const evmc::bytes32& block_hash) {
    const silkworm::ByteView block_hash_bytes{block_hash.bytes, silkworm::kHashLength};
    const auto value{co_await reader.get_one(db::table::kHeaderNumbersName, block_hash_bytes)};
    if (value.empty()) {
        throw std::invalid_argument{"empty block number value in read_header_number"};
    }
    co_return boost::endian::load_big_u64(value.data());
}

boost::asio::awaitable<ChainConfig> read_chain_config(const DatabaseReader& reader) {
    const auto genesis_block_hash{co_await read_canonical_block_hash(reader, kEarliestBlockNumber)};
    SILK_DEBUG << "rawdb::read_chain_config genesis_block_hash: " << genesis_block_hash;
    const silkworm::ByteView genesis_block_hash_bytes{genesis_block_hash.bytes, silkworm::kHashLength};
    const auto data{co_await reader.get_one(db::table::kConfigName, genesis_block_hash_bytes)};
    if (data.empty()) {
        throw std::invalid_argument{"empty chain config data in read_chain_config"};
    }
    SILK_DEBUG << "rawdb::read_chain_config chain config data: " << data.c_str();
    const auto json_config = nlohmann::json::parse(data.c_str());
    SILK_TRACE << "rawdb::read_chain_config chain config JSON: " << json_config.dump();
    co_return ChainConfig{genesis_block_hash, json_config};
}

boost::asio::awaitable<uint64_t> read_chain_id(const DatabaseReader& reader) {
    const auto chain_info = co_await read_chain_config(reader);
    if (chain_info.config.count("chainId") == 0) {
        throw std::runtime_error{"missing chainId in chain config"};
    }
    co_return chain_info.config["chainId"].get<uint64_t>();
}

boost::asio::awaitable<evmc::bytes32> read_canonical_block_hash(const DatabaseReader& reader, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    SILK_TRACE << "rawdb::read_canonical_block_hash block_key: " << silkworm::to_hex(block_key);
    const auto value{co_await reader.get_one(db::table::kCanonicalHashesName, block_key)};
    if (value.empty()) {
        throw std::invalid_argument{"empty block hash value in read_canonical_block_hash"};
    }
    const auto canonical_block_hash{silkworm::to_bytes32(value)};
    SILK_DEBUG << "rawdb::read_canonical_block_hash canonical block hash: " << canonical_block_hash;
    co_return canonical_block_hash;
}

boost::asio::awaitable<intx::uint256> read_total_difficulty(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    SILK_TRACE << "rawdb::read_total_difficulty block_key: " << silkworm::to_hex(block_key);
    const auto result{co_await reader.get_one(db::table::kDifficultyName, block_key)};
    if (result.empty()) {
        throw std::invalid_argument{"empty total difficulty value in read_total_difficulty"};
    }
    silkworm::ByteView value{result};
    intx::uint256 total_difficulty{0};
    auto decoding_result{silkworm::rlp::decode(value, total_difficulty)};
    if (!decoding_result) {
        throw std::runtime_error{"cannot RLP-decode total difficulty value in read_total_difficulty"};
    }
    SILK_DEBUG << "rawdb::read_total_difficulty canonical total difficulty: " << total_difficulty;
    co_return total_difficulty;
}

boost::asio::awaitable<std::shared_ptr<BlockWithHash>> read_block(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    auto block_with_hash_ptr = std::make_shared<silkworm::BlockWithHash>();
    block_with_hash_ptr->block.header = co_await read_header(reader, block_hash, block_number);
    SILK_TRACE << "header: number=" << block_with_hash_ptr->block.header.number;
    auto body = co_await read_body(reader, block_hash, block_number);
    SILK_TRACE << "body: #txn=" << body.transactions.size() << " #ommers=" << body.ommers.size();
    block_with_hash_ptr->block.transactions = std::move(body.transactions);
    block_with_hash_ptr->block.ommers = std::move(body.ommers),
    block_with_hash_ptr->block.withdrawals = std::move(body.withdrawals),
    block_with_hash_ptr->hash = block_hash;
    co_return block_with_hash_ptr;
}

boost::asio::awaitable<silkworm::BlockHeader> read_header_by_hash(const DatabaseReader& reader, const evmc::bytes32& block_hash) {
    const auto block_number = co_await read_header_number(reader, block_hash);
    co_return co_await read_header(reader, block_hash, block_number);
}

boost::asio::awaitable<silkworm::BlockHeader> read_header_by_number(const DatabaseReader& reader, uint64_t block_number) {
    const auto block_hash = co_await read_canonical_block_hash(reader, block_number);
    co_return co_await read_header(reader, block_hash, block_number);
}

boost::asio::awaitable<silkworm::BlockHeader> read_header(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    auto data = co_await read_header_rlp(reader, block_hash, block_number);
    if (data.empty()) {
        throw std::runtime_error{"empty block header RLP in read_header"};
    }
    SILK_TRACE << "data: " << silkworm::to_hex(data);
    silkworm::ByteView data_view{data};
    silkworm::BlockHeader header{};
    const auto error = silkworm::rlp::decode(data_view, header);
    if (!error) {
        throw std::runtime_error{"invalid RLP decoding for block header"};
    }
    co_return header;
}

boost::asio::awaitable<silkworm::BlockHeader> read_current_header(const DatabaseReader& reader) {
    const auto head_header_hash = co_await read_head_header_hash(reader);
    co_return co_await read_header_by_hash(reader, head_header_hash);
}

boost::asio::awaitable<evmc::bytes32> read_head_header_hash(const DatabaseReader& reader) {
    const silkworm::Bytes kHeadHeaderKey = silkworm::bytes_of_string(db::table::kHeadHeaderName);
    const auto value = co_await reader.get_one(db::table::kHeadHeaderName, kHeadHeaderKey);
    if (value.empty()) {
        throw std::invalid_argument{"empty head header hash value in read_head_header_hash"};
    }
    const auto head_header_hash{silkworm::to_bytes32(value)};
    SILK_DEBUG << "head header hash: " << head_header_hash;
    co_return head_header_hash;
}

boost::asio::awaitable<uint64_t> read_cumulative_transaction_count(const DatabaseReader& reader, uint64_t block_number) {
    const auto block_hash = co_await read_canonical_block_hash(reader, block_number);
    const auto data = co_await read_body_rlp(reader, block_hash, block_number);
    if (data.empty()) {
        throw std::runtime_error{"empty block body RLP in read_body"};
    }
    SILK_TRACE << "RLP data for block body #" << block_number << ": " << silkworm::to_hex(data);

    try {
        silkworm::ByteView data_view{data};
        auto stored_body{silkworm::db::detail::decode_stored_block_body(data_view)};
        // 1 system txn in the beginning of block, and 1 at the end
        SILK_DEBUG << "base_txn_id: " << stored_body.base_txn_id + 1 << " txn_count: " << stored_body.txn_count - 2;
        co_return stored_body.base_txn_id + stored_body.txn_count - 1;
    } catch (const silkworm::DecodingException& error) {
        SILK_ERROR << "RLP decoding error for block body #" << block_number << " [" << error.what() << "]";
        throw std::runtime_error{"RLP decoding error for block body [" + std::string(error.what()) + "]"};
    }
}

boost::asio::awaitable<silkworm::BlockBody> read_body(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto data = co_await read_body_rlp(reader, block_hash, block_number);
    if (data.empty()) {
        throw std::runtime_error{"empty block body RLP in read_body"};
    }
    SILK_TRACE << "RLP data for block body #" << block_number << ": " << silkworm::to_hex(data);

    try {
        silkworm::ByteView data_view{data};
        auto stored_body{silkworm::db::detail::decode_stored_block_body(data_view)};
        // If block contains no txn, we're done
        if (stored_body.txn_count == 0) {
            co_return BlockBody{{}, std::move(stored_body.ommers), std::move(stored_body.withdrawals)};
        }
        // 1 system txn at the beginning of block and 1 at the end
        SILK_DEBUG << "base_txn_id: " << stored_body.base_txn_id + 1 << " txn_count: " << stored_body.txn_count - 2;
        auto transactions = co_await read_canonical_transactions(reader, stored_body.base_txn_id + 1, stored_body.txn_count - 2);
        if (!transactions.empty()) {
            const auto senders = co_await read_senders(reader, block_hash, block_number);
            if (senders.size() == transactions.size()) {
                // Fill sender in transactions
                for (size_t i{0}; i < transactions.size(); i++) {
                    transactions[i].from = senders[i];
                }
            } else {
                // Transaction sender will be recovered on-the-fly (performance penalty)
                SILK_WARN << "#senders: " << senders.size() << " and #txns " << transactions.size() << " do not match";
            }
        }
        co_return BlockBody{std::move(transactions), std::move(stored_body.ommers), std::move(stored_body.withdrawals)};
    } catch (const silkworm::DecodingException& error) {
        SILK_ERROR << "RLP decoding error for block body #" << block_number << " [" << error.what() << "]";
        throw std::runtime_error{"RLP decoding error for block body [" + std::string(error.what()) + "]"};
    }
}

boost::asio::awaitable<silkworm::Bytes> read_header_rlp(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    co_return co_await reader.get_one(db::table::kHeadersName, block_key);
}

boost::asio::awaitable<silkworm::Bytes> read_body_rlp(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    co_return co_await reader.get_one(db::table::kBlockBodiesName, block_key);
}

boost::asio::awaitable<Addresses> read_senders(const DatabaseReader& reader, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    const auto data = co_await reader.get_one(db::table::kSendersName, block_key);
    SILK_TRACE << "read_senders data: " << silkworm::to_hex(data);
    Addresses senders{data.size() / silkworm::kAddressLength};
    for (size_t i{0}; i < senders.size(); i++) {
        senders[i] = silkworm::to_evmc_address(silkworm::ByteView{&data[i * silkworm::kAddressLength], silkworm::kAddressLength});
    }
    co_return senders;
}

boost::asio::awaitable<Receipts> read_raw_receipts(const DatabaseReader& reader, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const auto data = co_await reader.get_one(db::table::kBlockReceiptsName, block_key);
    SILK_TRACE << "read_raw_receipts data: " << silkworm::to_hex(data);
    if (data.empty()) {
        co_return Receipts{};  // TODO(canepat): use std::null_opt with boost::asio::awaitable<std::optional<Receipts>>?
    }
    Receipts receipts{};
    const bool decoding_ok{cbor_decode(data, receipts)};
    if (!decoding_ok) {
        SILK_WARN << "cannot decode raw receipts in block: " << block_number;
        co_return receipts;
    }
    SILK_DEBUG << "#receipts: " << receipts.size();

    auto log_key = silkworm::db::log_key(block_number, 0);
    SILK_DEBUG << "log_key: " << silkworm::to_hex(log_key);
    Walker walker = [&](const silkworm::Bytes& k, const silkworm::Bytes& v) {
        if (k.size() != sizeof(uint64_t) + sizeof(uint32_t)) {
            return false;
        }
        auto tx_id = boost::endian::load_big_u32(&k[sizeof(uint64_t)]);
        const bool decode_ok{cbor_decode(v, receipts[tx_id].logs)};
        if (!decode_ok) {
            SILK_WARN << "cannot decode logs for receipt: " << tx_id << " in block: " << block_number;
            return false;
        }
        receipts[tx_id].bloom = bloom_from_logs(receipts[tx_id].logs);
        SILK_DEBUG << "#receipts[" << tx_id << "].logs: " << receipts[tx_id].logs.size();
        return true;
    };
    co_await reader.walk(db::table::kLogsName, log_key, 8 * CHAR_BIT, walker);

    co_return receipts;
}

boost::asio::awaitable<Receipts> read_receipts(const DatabaseReader& reader, const silkworm::BlockWithHash& block_with_hash) {
    const evmc::bytes32 block_hash = block_with_hash.hash;
    uint64_t block_number = block_with_hash.block.header.number;
    auto receipts = co_await read_raw_receipts(reader, block_number);

    // Add derived fields to the receipts
    auto transactions = block_with_hash.block.transactions;
    SILK_DEBUG << "#transactions=" << block_with_hash.block.transactions.size() << " #receipts=" << receipts.size();
    if (transactions.size() != receipts.size()) {
        throw std::runtime_error{"#transactions and #receipts do not match in read_receipts"};
    }
    uint32_t log_index{0};
    for (size_t i{0}; i < receipts.size(); i++) {
        // The tx hash can be calculated by the tx content itself
        auto tx_hash{hash_of_transaction(transactions[i])};
        receipts[i].tx_hash = silkworm::to_bytes32(full_view(tx_hash.bytes));
        receipts[i].tx_index = uint32_t(i);

        receipts[i].block_hash = block_hash;
        receipts[i].block_number = block_number;

        // When tx receiver is not set, create a contract with address depending on tx sender and its nonce
        if (!transactions[i].to.has_value()) {
            receipts[i].contract_address = silkworm::create_address(*transactions[i].from, transactions[i].nonce);
        }

        // The gas used can be calculated by the previous receipt
        if (i == 0) {
            receipts[i].gas_used = receipts[i].cumulative_gas_used;
        } else {
            receipts[i].gas_used = receipts[i].cumulative_gas_used - receipts[i - 1].cumulative_gas_used;
        }

        receipts[i].from = transactions[i].from;
        receipts[i].to = transactions[i].to;
        receipts[i].type = static_cast<uint8_t>(transactions[i].type);

        // The derived fields of receipt are taken from block and transaction
        for (size_t j{0}; j < receipts[i].logs.size(); j++) {
            receipts[i].logs[j].block_number = block_number;
            receipts[i].logs[j].block_hash = block_hash;
            receipts[i].logs[j].tx_hash = receipts[i].tx_hash;
            receipts[i].logs[j].tx_index = uint32_t(i);
            receipts[i].logs[j].index = log_index++;
            receipts[i].logs[j].removed = false;
        }
    }

    co_return receipts;
}

boost::asio::awaitable<Transactions> read_canonical_transactions(const DatabaseReader& reader, uint64_t base_txn_id, uint64_t txn_count) {
    Transactions txns{};
    if (txn_count == 0) {
        SILK_DEBUG << "txn_count: 0 #txns: 0";
        co_return txns;
    }

    txns.reserve(txn_count);

    silkworm::Bytes txn_id_key(8, '\0');
    boost::endian::store_big_u64(txn_id_key.data(), base_txn_id);
    SILK_DEBUG << "txn_count: " << txn_count << " txn_id_key: " << silkworm::to_hex(txn_id_key);
    size_t i{0};
    Walker walker = [&](const silkworm::Bytes&, const silkworm::Bytes& v) {
        SILK_TRACE << "v: " << silkworm::to_hex(v);
        silkworm::ByteView value{v};
        silkworm::Transaction tx{};
        const auto error = silkworm::rlp::decode(value, tx);
        if (!error) {
            SILK_ERROR << "invalid RLP decoding for transaction index " << i;
            return false;
        }
        SILK_TRACE << "index: " << i << " tx_hash: " << silkworm::to_hex({hash_of(v).bytes, silkworm::kHashLength});
        txns.emplace(txns.end(), std::move(tx));
        i++;
        return i < txn_count;
    };
    co_await reader.walk(db::table::kBlockTransactionsName, txn_id_key, 0, walker);

    SILK_DEBUG << "#txns: " << txns.size();

    co_return txns;
}

boost::asio::awaitable<Transactions> read_noncanonical_transactions(const DatabaseReader& reader, uint64_t base_txn_id, uint64_t txn_count) {
    Transactions txns{};
    if (txn_count == 0) {
        SILK_DEBUG << "txn_count: 0 #txns: 0";
        co_return txns;
    }
    txns.reserve(txn_count);
    silkworm::Bytes txn_id_key(8, '\0');
    boost::endian::store_big_u64(txn_id_key.data(), base_txn_id);
    SILK_DEBUG << "txn_count: " << txn_count << " txn_id_key: " << silkworm::to_hex(txn_id_key);
    size_t i{0};
    Walker walker = [&](const silkworm::Bytes&, const silkworm::Bytes& v) {
        SILK_TRACE << "v: " << silkworm::to_hex(v);
        silkworm::ByteView value{v};
        silkworm::Transaction tx{};
        const auto error = silkworm::rlp::decode(value, tx);
        if (!error) {
            SILK_ERROR << "invalid RLP decoding for transaction index " << i;
            return false;
        }
        SILK_TRACE << "index: " << i << " tx_hash: " << silkworm::to_hex({hash_of(v).bytes, silkworm::kHashLength});
        txns.emplace(txns.end(), std::move(tx));
        i++;
        return i < txn_count;
    };
    co_await reader.walk(db::table::kNonCanonicalTransactionsName, txn_id_key, 0, walker);
    SILK_DEBUG << "#txns: " << txns.size();
    co_return txns;
}

boost::asio::awaitable<intx::uint256> read_total_issued(const core::rawdb::DatabaseReader& reader, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const auto value = co_await reader.get_one(db::table::kIssuanceName, block_key);
    intx::uint256 total_issued = 0;
    if (!value.empty()) {
        total_issued = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_total_issued: " << total_issued;
    co_return total_issued;
}

boost::asio::awaitable<intx::uint256> read_total_burnt(const core::rawdb::DatabaseReader& reader, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const std::string kBurnt{"burnt"};
    silkworm::Bytes key{kBurnt.begin(), kBurnt.end()};
    key.append(block_key.begin(), block_key.end());
    const auto value = co_await reader.get_one(db::table::kIssuanceName, key);
    intx::uint256 total_burnt = 0;
    if (!value.empty()) {
        total_burnt = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_total_burnt: " << total_burnt;
    co_return total_burnt;
}

boost::asio::awaitable<intx::uint256> read_cumulative_gas_used(const core::rawdb::DatabaseReader& reader, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const auto value = co_await reader.get_one(db::table::kCumulativeGasIndexName, block_key);
    intx::uint256 cumulative_gas_index = 0;
    if (!value.empty()) {
        cumulative_gas_index = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_cumulative_gas_used: " << cumulative_gas_index;
    co_return cumulative_gas_index;
}

}  // namespace silkworm::rpc::core::rawdb
