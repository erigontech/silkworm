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

#include "remote_chain_storage.hpp"

#include <utility>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>

#include "chain.hpp"

namespace silkworm::db::chain {

RemoteChainStorage::RemoteChainStorage(kv::api::Transaction& tx, Providers providers)
    : tx_{tx}, providers_{std::move(providers)} {}

Task<ChainConfig> RemoteChainStorage::read_chain_config() const {
    const auto genesis_block_hash{co_await providers_.canonical_block_hash_from_number(kEarliestBlockNumber)};
    if (!genesis_block_hash) {
        throw std::runtime_error{"cannot read genesis block hash in read_chain_config"};
    }
    SILK_DEBUG << "rawdb::read_chain_config genesis_block_hash: " << to_hex(genesis_block_hash->bytes);
    const ByteView genesis_block_hash_bytes{genesis_block_hash->bytes, kHashLength};
    const auto data{co_await tx_.get_one(db::table::kConfigName, genesis_block_hash_bytes)};
    if (data.empty()) {
        throw std::invalid_argument{"empty chain config data in read_chain_config"};
    }
    SILK_DEBUG << "rawdb::read_chain_config chain config data: " << data.c_str();
    const auto json_config = nlohmann::json::parse(data.begin(), data.end());
    SILK_TRACE << "rawdb::read_chain_config chain config JSON: " << json_config.dump();
    std::optional<ChainConfig> chain_config = ChainConfig::from_json(json_config);
    if (!chain_config) {
        throw std::runtime_error{"invalid chain config JSON in read_chain_config"};
    }
    chain_config->genesis_hash = *genesis_block_hash;
    co_return *chain_config;
}

Task<BlockNum> RemoteChainStorage::highest_block_number() const {
    throw std::logic_error{"RemoteChainStorage::highest_block_number not implemented"};
}

Task<std::optional<BlockNum>> RemoteChainStorage::read_block_number(const Hash& hash) const {
    co_return co_await providers_.block_number_from_hash(hash.bytes);
}

Task<bool> RemoteChainStorage::read_block(HashAsSpan hash, BlockNum number, bool read_senders, Block& block) const {
    co_return co_await providers_.block(number, hash, read_senders, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, BlockNum number, Block& block) const {
    co_return co_await providers_.block(number, hash.bytes, /*.read_senders=*/false, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, Block& block) const {
    const auto block_number = co_await providers_.block_number_from_hash(hash.bytes);
    if (!block_number) {
        co_return false;
    }
    co_return co_await providers_.block(*block_number, hash.bytes, /*.read_senders=*/false, block);
}

Task<bool> RemoteChainStorage::read_block(BlockNum number, bool read_senders, Block& block) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(number);
    if (!hash) {
        co_return false;
    }
    co_return co_await providers_.block(number, hash->bytes, read_senders, block);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum number, HashAsArray hash) const {
    Block block;
    const bool success = co_await providers_.block(number, hash, /*.read_senders=*/false, block);
    std::optional<BlockHeader> header;
    if (success) {
        header = std::move(block.header);
    }
    co_return header;
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum number, const Hash& hash) const {
    co_return co_await read_header(number, hash.bytes);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(const Hash& hash) const {
    const auto number = co_await providers_.block_number_from_hash(hash.bytes);
    if (!number) {
        co_return std::nullopt;
    }
    SILK_DEBUG << "RemoteChainStorage::read_header: " << silkworm::to_hex(hash) << " number: " << *number;
    co_return co_await read_header(*number, hash.bytes);
}

Task<std::vector<BlockHeader>> RemoteChainStorage::read_sibling_headers(BlockNum /*number*/) const {
    throw std::logic_error{"RemoteChainStorage::read_sibling_headers not implemented"};
}

Task<bool> RemoteChainStorage::read_body(BlockNum number, HashAsArray hash, bool read_senders, BlockBody& body) const {
    Block block;
    const bool success = co_await providers_.block(number, hash, read_senders, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockNum number, BlockBody& body) const {
    co_return co_await read_body(number, hash.bytes, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockBody& body) const {
    const auto number = co_await providers_.block_number_from_hash(hash.bytes);
    if (!number) {
        co_return false;
    }
    co_return co_await read_body(*number, hash.bytes, /*.read_senders=*/false, body);
}

Task<std::optional<Hash>> RemoteChainStorage::read_canonical_header_hash(BlockNum number) const {
    co_return co_await providers_.canonical_block_hash_from_number(number);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_canonical_header(BlockNum number) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(number);
    if (!hash) {
        co_return std::nullopt;
    }
    co_return co_await read_header(number, *hash);
}

Task<bool> RemoteChainStorage::read_canonical_body(BlockNum number, BlockBody& body) const {
    Block block;
    const auto hash = co_await providers_.canonical_block_hash_from_number(number);
    if (!hash) {
        co_return false;
    }
    const bool success = co_await providers_.block(number, hash->bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<bool> RemoteChainStorage::read_canonical_block(BlockNum number, Block& block) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(number);
    if (!hash) {
        co_return false;
    }
    const bool success = co_await providers_.block(number, hash->bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    co_return true;
}

Task<bool> RemoteChainStorage::has_body(BlockNum number, HashAsArray hash) const {
    BlockBody body;
    co_return co_await read_body(number, hash, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::has_body(BlockNum number, const Hash& hash) const {
    BlockBody body;
    co_return co_await read_body(hash, number, body);
}

Task<bool> RemoteChainStorage::read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    Block block;
    const bool success = co_await providers_.block(number, hash.bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    rlp_txs.reserve(block.transactions.size());
    for (const auto& transaction : block.transactions) {
        rlp::encode(rlp_txs.emplace_back(), transaction);
    }
    co_return true;
}

Task<bool> RemoteChainStorage::read_rlp_transaction(const evmc::bytes32& /*txn_hash*/, Bytes& /*rlp_tx*/) const {
    throw std::logic_error{"RemoteChainStorage::read_rlp_transaction not implemented"};
}

Task<std::optional<intx::uint256>> RemoteChainStorage::read_total_difficulty(const Hash& hash, BlockNum number) const {
    co_return co_await db::chain::read_total_difficulty(tx_, hash, number);
}

Task<std::optional<BlockNum>> RemoteChainStorage::read_block_number_by_transaction_hash(const evmc::bytes32& transaction_hash) const {
    co_return co_await providers_.block_number_from_txn_hash(transaction_hash.bytes);
}

Task<std::optional<Transaction>> RemoteChainStorage::read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_id) const {
    const auto block_hash = co_await read_canonical_header_hash(block_num);
    if (!block_hash) {
        co_return std::nullopt;
    }
    BlockBody body;
    if (const bool success = co_await read_body(*block_hash, block_num, body); !success) {
        co_return std::nullopt;
    }
    if (txn_id >= body.transactions.size()) {
        co_return std::nullopt;
    }
    co_return body.transactions[txn_id];
}

}  // namespace silkworm::db::chain
