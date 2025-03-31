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

#include "local_chain_storage.hpp"

#include <bit>
#include <stdexcept>

#include <silkworm/db/access_layer.hpp>

namespace silkworm::db::chain {

Task<ChainConfig> LocalChainStorage::read_chain_config() const {
    const auto chain_config{data_model_.read_chain_config()};
    if (!chain_config) {
        throw std::runtime_error{"empty chain config data in storage"};
    }
    co_return *chain_config;
}

Task<BlockNum> LocalChainStorage::max_block_num() const {
    co_return data_model_.max_block_num();
}

Task<std::optional<BlockNum>> LocalChainStorage::read_block_num(const Hash& hash) const {
    co_return data_model_.read_block_num(hash);
}

Task<bool> LocalChainStorage::read_block(HashAsSpan hash, BlockNum block_num, bool read_senders, Block& block) const {
    co_return data_model_.read_block(hash, block_num, read_senders, block);
}

Task<bool> LocalChainStorage::read_block(const Hash& hash, BlockNum block_num, Block& block) const {
    co_return data_model_.read_block(hash, block_num, block);
}

Task<bool> LocalChainStorage::read_block(const Hash& hash, Block& block) const {
    const auto block_num = co_await read_block_num(hash);
    if (!block_num) {
        co_return false;
    }
    co_return co_await read_block(hash, *block_num, block);
}

Task<bool> LocalChainStorage::read_block(BlockNum block_num, bool read_senders, Block& block) const {
    co_return data_model_.read_block(block_num, read_senders, block);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(BlockNum block_num, HashAsArray hash) const {
    co_return data_model_.read_header(block_num, hash);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(BlockNum block_num, const Hash& hash) const {
    co_return data_model_.read_header(block_num, hash);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(const Hash& hash) const {
    co_return data_model_.read_header(hash);
}

Task<std::vector<BlockHeader>> LocalChainStorage::read_sibling_headers(BlockNum block_num) const {
    co_return data_model_.read_sibling_headers(block_num);
}

Task<bool> LocalChainStorage::read_body(BlockNum block_num, HashAsArray hash, bool read_senders, BlockBody& body) const {
    co_return data_model_.read_body(block_num, hash, read_senders, body);
}

Task<bool> LocalChainStorage::read_body(const Hash& hash, BlockNum block_num, BlockBody& body) const {
    co_return data_model_.read_body(hash, block_num, body);
}

Task<bool> LocalChainStorage::read_body(const Hash& hash, BlockBody& body) const {
    co_return data_model_.read_body(hash, body);
}

Task<std::optional<Hash>> LocalChainStorage::read_canonical_header_hash(BlockNum block_num) const {
    co_return data_model_.read_canonical_header_hash(block_num);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_canonical_header(BlockNum block_num) const {
    co_return data_model_.read_canonical_header(block_num);
}

Task<bool> LocalChainStorage::read_canonical_body(BlockNum block_num, BlockBody& body) const {
    co_return data_model_.read_canonical_body(block_num, body);
}

Task<std::optional<Bytes>> LocalChainStorage::read_raw_canonical_body_for_storage(BlockNum block_num) const {
    co_return data_model_.read_raw_canonical_body_for_storage(block_num);
}

Task<bool> LocalChainStorage::read_canonical_block(BlockNum block_num, Block& block) const {
    co_return data_model_.read_canonical_block(block_num, block);
}

Task<bool> LocalChainStorage::has_body(BlockNum block_num, HashAsArray hash) const {
    co_return data_model_.has_body(block_num, hash);
}

Task<bool> LocalChainStorage::has_body(BlockNum block_num, const Hash& hash) const {
    co_return data_model_.has_body(block_num, hash);
}

Task<bool> LocalChainStorage::read_rlp_transactions(BlockNum block_num, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    co_return data_model_.read_rlp_transactions(block_num, hash, rlp_txs);
}

Task<bool> LocalChainStorage::read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const {
    auto [block_num, txn_id] = data_model_.read_tx_lookup(txn_hash);
    if (!block_num) {
        co_return false;
    }
    auto block_hash = data_model_.read_canonical_header_hash(*block_num);
    if (!block_hash) {
        co_return false;
    }
    std::vector<Bytes> rlp_txs;
    if (!co_await read_rlp_transactions(*block_num, *block_hash, rlp_txs)) {
        co_return false;
    }
    for (const auto& rlp : rlp_txs) {
        if (std::bit_cast<evmc_bytes32>(keccak256(rlp)) == txn_hash) {
            rlp_tx = rlp;
            co_return true;
        }
    }
    co_return false;
}

Task<std::optional<intx::uint256>> LocalChainStorage::read_total_difficulty(const Hash& hash, BlockNum block_num) const {
    co_return data_model_.read_total_difficulty(block_num, hash);
}

Task<std::pair<std::optional<BlockNum>, std::optional<TxnId>>> LocalChainStorage::read_block_num_by_transaction_hash(const evmc::bytes32& transaction_hash) const {
    co_return data_model_.read_tx_lookup(transaction_hash);
}

Task<std::optional<Transaction>> LocalChainStorage::read_transaction_by_idx_in_block(BlockNum block_num, uint64_t txn_idx) const {
    co_return data_model_.read_transaction_by_txn_idx(block_num, txn_idx);
}

Task<std::pair<std::optional<BlockHeader>, std::optional<Hash>>> LocalChainStorage::read_head_header_and_hash() const {
    co_return data_model_.read_head_header_and_hash();
}

}  // namespace silkworm::db::chain
