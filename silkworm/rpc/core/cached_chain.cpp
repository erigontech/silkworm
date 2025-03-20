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

#include "cached_chain.hpp"

#include <silkworm/rpc/core/block_reader.hpp>

namespace silkworm::rpc::core {

Task<std::shared_ptr<BlockWithHash>> read_block_by_number(BlockCache& cache, const db::chain::ChainStorage& storage, BlockNum block_num) {
    const auto block_hash = co_await storage.read_canonical_header_hash(block_num);
    if (!block_hash) {
        co_return nullptr;
    }
    const auto cached_block = cache.get(*block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    const auto block_with_hash = std::make_shared<BlockWithHash>();
    const auto block_found = co_await storage.read_block(block_hash->bytes, block_num, /*read_senders */ true, block_with_hash->block);
    if (!block_found) {
        co_return nullptr;
    }
    block_with_hash->hash = *block_hash;
    if (!block_with_hash->block.transactions.empty()) {
        // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
        // but block can in the future become canonical(inserted in main chain) with its transactions
        cache.insert(*block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

Task<std::shared_ptr<BlockWithHash>> read_block_by_hash(BlockCache& cache, const db::chain::ChainStorage& storage, const evmc::bytes32& block_hash) {
    const auto cached_block = cache.get(block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    const auto block_with_hash = std::make_shared<BlockWithHash>();
    const auto block_num = co_await storage.read_block_num(block_hash);
    if (!block_num) {
        co_return nullptr;
    }
    const auto block_found = co_await storage.read_block(block_hash.bytes, *block_num, /*read_senders */ true, block_with_hash->block);
    if (!block_found) {
        co_return nullptr;
    }
    block_with_hash->hash = block_hash;
    if (!block_with_hash->block.transactions.empty()) {
        // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
        // but block can in the future become canonical(inserted in main chain) with its transactions
        cache.insert(block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

Task<std::shared_ptr<BlockWithHash>> read_block_by_block_num_or_hash(BlockCache& cache,
                                                                     const db::chain::ChainStorage& storage,
                                                                     db::kv::api::Transaction& tx,
                                                                     const BlockNumOrHash& block_num_or_hash) {
    if (block_num_or_hash.is_number()) {  // NOLINT(bugprone-branch-clone)
        co_return co_await read_block_by_number(cache, storage, block_num_or_hash.number());
    } else if (block_num_or_hash.is_hash()) {
        co_return co_await read_block_by_hash(cache, storage, block_num_or_hash.hash());
    } else if (block_num_or_hash.is_tag()) {
        rpc::BlockReader block_reader{storage, tx};
        auto [block_num, ignore] = co_await block_reader.get_block_num(block_num_or_hash.tag(), /*latest_required=*/false);
        co_return co_await read_block_by_number(cache, storage, block_num);
    }
    throw std::runtime_error{"invalid block_num_or_hash value"};
}

Task<std::shared_ptr<BlockWithHash>> read_block_by_transaction_hash(BlockCache& cache, const db::chain::ChainStorage& storage, const evmc::bytes32& transaction_hash) {
    const auto block_num = co_await storage.read_block_num_by_transaction_hash(transaction_hash);
    if (!block_num) {
        co_return nullptr;
    }
    const auto block_by_hash = co_await read_block_by_number(cache, storage, *block_num);
    if (!block_by_hash) {
        co_return nullptr;
    }
    co_return block_by_hash;
}

Task<std::optional<TransactionWithBlock>> read_transaction_by_hash(BlockCache& cache, const db::chain::ChainStorage& storage, const evmc::bytes32& transaction_hash) {
    const auto block_num = co_await storage.read_block_num_by_transaction_hash(transaction_hash);
    if (!block_num) {
        co_return std::nullopt;
    }
    const auto block_with_hash = co_await read_block_by_number(cache, storage, *block_num);
    if (!block_with_hash) {
        co_return std::nullopt;
    }
    const auto& transactions = block_with_hash->block.transactions;
    for (size_t idx{0}; idx < transactions.size(); ++idx) {
        if (transaction_hash == transactions[idx].hash()) {
            const auto& block_header = block_with_hash->block.header;
            co_return TransactionWithBlock{
                block_with_hash,
                {transactions[idx], block_with_hash->hash, block_header.number, block_header.base_fee_per_gas, idx}};
        }
    }
    co_return std::nullopt;
}

}  // namespace silkworm::rpc::core
