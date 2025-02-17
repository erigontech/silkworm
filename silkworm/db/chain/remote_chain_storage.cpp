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
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::chain {

RemoteChainStorage::RemoteChainStorage(kv::api::Transaction& tx, Providers providers)
    : tx_{tx}, providers_{std::move(providers)} {}

Task<ChainConfig> RemoteChainStorage::read_chain_config() const {
    const auto genesis_block_hash{co_await providers_.canonical_block_hash_from_number(kEarliestBlockNum)};
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

Task<BlockNum> RemoteChainStorage::max_block_num() const {
    throw std::logic_error{"RemoteChainStorage::max_block_num not implemented"};
}

Task<std::optional<BlockNum>> RemoteChainStorage::read_block_num(const Hash& hash) const {
    co_return co_await providers_.block_num_from_hash(hash.bytes);
}

Task<bool> RemoteChainStorage::read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const {
    co_return co_await providers_.block(block_num, hash, read_senders, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, BlockNum block_num, Block& block) const {
    co_return co_await providers_.block(block_num, hash.bytes, /*.read_senders=*/false, block);
}

Task<bool> RemoteChainStorage::read_block(const Hash& hash, Block& block) const {
    const auto block_num = co_await providers_.block_num_from_hash(hash.bytes);
    if (!block_num) {
        co_return false;
    }
    co_return co_await providers_.block(*block_num, hash.bytes, /*.read_senders=*/false, block);
}

Task<bool> RemoteChainStorage::read_block(BlockNum block_num, bool read_senders, Block& block) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(block_num);
    if (!hash) {
        co_return false;
    }
    co_return co_await providers_.block(block_num, hash->bytes, read_senders, block);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum block_num, HashAsArray hash) const {
    Block block;
    const bool success = co_await providers_.block(block_num, hash, /*.read_senders=*/false, block);
    std::optional<BlockHeader> header;
    if (success) {
        header = std::move(block.header);
    }
    co_return header;
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(BlockNum block_num, const Hash& hash) const {
    co_return co_await read_header(block_num, hash.bytes);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_header(const Hash& hash) const {
    const auto block_num = co_await providers_.block_num_from_hash(hash.bytes);
    if (!block_num) {
        co_return std::nullopt;
    }
    SILK_DEBUG << "RemoteChainStorage::read_header: " << silkworm::to_hex(hash) << " number: " << *block_num;
    co_return co_await read_header(*block_num, hash.bytes);
}

Task<std::vector<BlockHeader>> RemoteChainStorage::read_sibling_headers(BlockNum /*block_num*/) const {
    throw std::logic_error{"RemoteChainStorage::read_sibling_headers not implemented"};
}

Task<bool> RemoteChainStorage::read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const {
    Block block;
    const bool success = co_await providers_.block(block_num, hash, read_senders, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const {
    co_return co_await read_body(block_num, hash.bytes, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::read_body(const Hash& hash, BlockBody& body) const {
    const auto block_num = co_await providers_.block_num_from_hash(hash.bytes);
    if (!block_num) {
        co_return false;
    }
    co_return co_await read_body(*block_num, hash.bytes, /*.read_senders=*/false, body);
}

Task<std::optional<Hash>> RemoteChainStorage::read_canonical_header_hash(BlockNum block_num) const {
    co_return co_await providers_.canonical_block_hash_from_number(block_num);
}

Task<std::optional<BlockHeader>> RemoteChainStorage::read_canonical_header(BlockNum block_num) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(block_num);
    if (!hash) {
        co_return std::nullopt;
    }
    co_return co_await read_header(block_num, *hash);
}

Task<bool> RemoteChainStorage::read_canonical_body(BlockNum block_num, BlockBody& body) const {
    Block block;
    const auto hash = co_await providers_.canonical_block_hash_from_number(block_num);
    if (!hash) {
        co_return false;
    }
    const bool success = co_await providers_.block(block_num, hash->bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    body.transactions = std::move(block.transactions);
    body.ommers = std::move(block.ommers);
    body.withdrawals = std::move(block.withdrawals);
    co_return true;
}

Task<std::optional<Bytes>> RemoteChainStorage::read_raw_canonical_body_for_storage(BlockNum block_num) const {
    co_return co_await providers_.canonical_body_for_storage(block_num);
}

Task<bool> RemoteChainStorage::read_canonical_block(BlockNum block_num, Block& block) const {
    const auto hash = co_await providers_.canonical_block_hash_from_number(block_num);
    if (!hash) {
        co_return false;
    }
    const bool success = co_await providers_.block(block_num, hash->bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    co_return true;
}

Task<bool> RemoteChainStorage::has_body(BlockNum block_num, HashAsArray hash) const {
    BlockBody body;
    co_return co_await read_body(block_num, hash, /*.read_senders=*/false, body);
}

Task<bool> RemoteChainStorage::has_body(BlockNum block_num, const Hash& hash) const {
    BlockBody body;
    co_return co_await read_body(hash, block_num, body);
}

Task<bool> RemoteChainStorage::read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    Block block;
    const bool success = co_await providers_.block(block_num, hash.bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    rlp_txs.reserve(block.transactions.size());
    for (const auto& transaction : block.transactions) {
        rlp::encode(rlp_txs.emplace_back(), transaction, /*wrap_eip2718_into_string=*/false);
    }
    co_return true;
}

Task<bool> RemoteChainStorage::read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const {
    auto block_num = co_await providers_.block_num_from_txn_hash(txn_hash.bytes);
    if (!block_num) {
        co_return false;
    }

    const auto block_hash = co_await providers_.canonical_block_hash_from_number(*block_num);
    if (!block_hash) {
        co_return false;
    }

    Block block;
    const bool success = co_await providers_.block(*block_num, block_hash->bytes, /*.read_senders=*/false, block);
    if (!success) {
        co_return false;
    }
    for (const auto& transaction : block.transactions) {
        Bytes rlp;
        if (transaction.hash() == txn_hash) {
            rlp::encode(rlp, transaction, /*wrap_eip2718_into_string=*/false);
            rlp_tx = rlp;
            co_return true;
        }
    }
    co_return false;
}

Task<std::optional<intx::uint256>> RemoteChainStorage::read_total_difficulty(const Hash& hash, BlockNum block_num) const {
    const auto block_key = db::block_key(block_num, hash.bytes);
    SILK_TRACE << "read_total_difficulty block_key: " << to_hex(block_key);
    const auto result{co_await tx_.get_one(table::kDifficultyName, block_key)};
    if (result.empty()) {
        co_return std::nullopt;
    }
    ByteView value{result};
    intx::uint256 total_difficulty{0};
    auto decoding_result{rlp::decode(value, total_difficulty)};
    if (!decoding_result) {
        throw std::runtime_error{"cannot RLP-decode total difficulty value in read_total_difficulty"};
    }
    SILK_DEBUG << "read_total_difficulty canonical total difficulty: " << total_difficulty;
    co_return total_difficulty;
}

Task<std::optional<BlockNum>> RemoteChainStorage::read_block_num_by_transaction_hash(const evmc::bytes32& transaction_hash) const {
    co_return co_await providers_.block_num_from_txn_hash(transaction_hash.bytes);
}

Task<std::optional<Transaction>> RemoteChainStorage::read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_idx) const {
    const auto block_hash = co_await read_canonical_header_hash(block_num);
    if (!block_hash) {
        co_return std::nullopt;
    }
    BlockBody body;
    if (const bool success = co_await read_body(*block_hash, block_num, body); !success) {
        co_return std::nullopt;
    }
    if (txn_idx >= body.transactions.size()) {
        co_return std::nullopt;
    }
    co_return body.transactions[txn_idx];
}

Task<std::pair<std::optional<BlockHeader>, std::optional<Hash>>> RemoteChainStorage::read_head_header_and_hash() const {
    const auto value = co_await tx_.get_one(table::kHeadHeaderName, string_to_bytes(table::kHeadHeaderName));
    if (value.empty()) {
        throw std::runtime_error{"empty head header hash value in read_head_header_hash"};
    }
    const auto head_header_hash{to_bytes32(value)};
    SILK_DEBUG << "head header hash: " << to_hex(head_header_hash);

    auto header = co_await read_header(head_header_hash);

    Hash header_hash{head_header_hash};

    co_return std::pair{std::move(header), header_hash};
}

}  // namespace silkworm::db::chain
