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

#include <silkworm/core/types/transaction.hpp>
#include <silkworm/db/access_layer.hpp>

namespace silkworm::rpc {

LocalChainStorage::LocalChainStorage(db::ROTxn& txn) : data_model_{txn} {}

Task<std::optional<ChainConfig>> LocalChainStorage::read_chain_config() const {
    co_return data_model_.read_chain_config();
}

Task<BlockNum> LocalChainStorage::highest_block_number() const {
    co_return data_model_.highest_block_number();
}

Task<std::optional<BlockNum>> LocalChainStorage::read_block_number(const Hash& hash) const {
    co_return data_model_.read_block_number(hash);
}

Task<bool> LocalChainStorage::read_block(HashAsSpan hash, BlockNum number, bool read_senders, Block& block) const {
    co_return data_model_.read_block(hash, number, read_senders, block);
}

Task<bool> LocalChainStorage::read_block(const Hash& hash, BlockNum number, Block& block) const {
    co_return data_model_.read_block(hash, number, block);
}

Task<bool> LocalChainStorage::read_block(const Hash& hash, Block& block) const {
    const auto number{co_await read_block_number(hash)};
    if (!number) {
        co_return false;
    }
    co_return co_await read_block(hash, *number, block);
}

Task<bool> LocalChainStorage::read_block(BlockNum number, bool read_senders, Block& block) const {
    co_return data_model_.read_block(number, read_senders, block);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(BlockNum number, HashAsArray hash) const {
    co_return data_model_.read_header(number, hash);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(BlockNum number, const Hash& hash) const {
    co_return data_model_.read_header(number, hash);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_header(const Hash& hash) const {
    co_return data_model_.read_header(hash);
}

Task<std::vector<BlockHeader>> LocalChainStorage::read_sibling_headers(BlockNum number) const {
    co_return data_model_.read_sibling_headers(number);
}

Task<bool> LocalChainStorage::read_body(BlockNum number, HashAsArray hash, bool read_senders, BlockBody& body) const {
    co_return data_model_.read_body(number, hash, read_senders, body);
}

Task<bool> LocalChainStorage::read_body(const Hash& hash, BlockNum number, BlockBody& body) const {
    co_return data_model_.read_body(hash, number, body);
}

Task<bool> LocalChainStorage::read_body(const Hash& hash, BlockBody& body) const {
    co_return data_model_.read_body(hash, body);
}

Task<std::optional<Hash>> LocalChainStorage::read_canonical_hash(BlockNum number) const {
    co_return data_model_.read_canonical_hash(number);
}

Task<std::optional<BlockHeader>> LocalChainStorage::read_canonical_header(BlockNum number) const {
    co_return data_model_.read_canonical_header(number);
}

Task<bool> LocalChainStorage::read_canonical_body(BlockNum number, BlockBody& body) const {
    co_return data_model_.read_canonical_body(number, body);
}

Task<bool> LocalChainStorage::read_canonical_block(BlockNum number, Block& block) const {
    co_return data_model_.read_canonical_block(number, block);
}

Task<bool> LocalChainStorage::has_body(BlockNum number, HashAsArray hash) const {
    co_return data_model_.has_body(number, hash);
}

Task<bool> LocalChainStorage::has_body(BlockNum number, const Hash& hash) const {
    co_return data_model_.has_body(number, hash);
}

Task<bool> LocalChainStorage::read_rlp_transactions(BlockNum number, const evmc::bytes32& hash, std::vector<Bytes>& rlp_txs) const {
    co_return data_model_.read_rlp_transactions(number, hash, rlp_txs);
}

Task<bool> LocalChainStorage::read_rlp_transaction(const evmc::bytes32& txn_hash, Bytes& rlp_tx) const {
    auto block_number = data_model_.read_tx_lookup(txn_hash);
    if (!block_number) {
        co_return false;
    }
    auto block_hash = data_model_.read_canonical_hash(*block_number);
    if (!block_hash) {
        co_return false;
    }
    std::vector<Bytes> rlp_txs;
    if (!co_await read_rlp_transactions(*block_number, *block_hash, rlp_txs)) {
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

Task<std::optional<intx::uint256>> LocalChainStorage::read_total_difficulty(const Hash& hash, BlockNum number) const {
    co_return data_model_.read_total_difficulty(number, hash);
}

Task<std::optional<BlockNum>> LocalChainStorage::read_block_number_by_transaction_hash(const evmc::bytes32& transaction_hash) const {
    co_return data_model_.read_tx_lookup(transaction_hash);
}

}  // namespace silkworm::rpc
