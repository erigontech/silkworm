/*
    Copyright 2020 The Silkrpc Authors

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

#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

namespace silkrpc::core {

boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_number(BlockCache& cache, const rawdb::DatabaseReader& reader, uint64_t block_number) {
    const auto block_hash = co_await rawdb::read_canonical_block_hash(reader, block_number);
    const auto cached_block = cache.get(block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    auto block_with_hash = co_await rawdb::read_block(reader, block_hash, block_number);
    if (block_with_hash.block.transactions.size() != 0) {
       // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
       // but block can in the future become canonical(inserted in main chain) with its transactions
       cache.insert(block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& block_hash) {
    const auto cached_block = cache.get(block_hash);
    if (cached_block) {
        co_return cached_block.value();
    }
    auto block_with_hash = co_await rawdb::read_block_by_hash(reader, block_hash);
    if (block_with_hash.block.transactions.size() != 0) {
       // don't save empty (without txs) blocks to cache, if block become non-canonical (not in main chain), we remove it's transactions,
       // but block can in the future become canonical(inserted in main chain) with its transactions
       cache.insert(block_hash, block_with_hash);
    }
    co_return block_with_hash;
}

boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_number_or_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const silkrpc::BlockNumberOrHash& bnoh) {
    if (bnoh.is_number()) {
        co_return co_await read_block_by_number(cache, reader, bnoh.number());
    } else if (bnoh.is_hash()) {
        co_return co_await read_block_by_hash(cache, reader, bnoh.hash());
    } else if (bnoh.is_tag()) {
        auto [block_number, ignore] = co_await get_block_number(bnoh.tag(), reader, /*latest_required=*/false);
        co_return co_await read_block_by_number(cache, reader, block_number);
    }
    throw std::runtime_error{"invalid block_number_or_hash value"};
}

boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_transaction_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& transaction_hash) {
    auto block_number = co_await rawdb::read_block_number_by_transaction_hash(reader, transaction_hash);
    co_return co_await read_block_by_number(cache, reader, block_number);
}

boost::asio::awaitable<std::optional<silkrpc::TransactionWithBlock>> read_transaction_by_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& transaction_hash) {
    auto block_number = co_await rawdb::read_block_number_by_transaction_hash(reader, transaction_hash);
    auto block_with_hash = co_await read_block_by_number(cache, reader, block_number);
    const silkworm::ByteView tx_hash{transaction_hash.bytes, silkworm::kHashLength};

    const auto transactions = block_with_hash.block.transactions;
    for (std::size_t idx{0}; idx < transactions.size(); idx++) {
        auto ethash_hash{hash_of_transaction(transactions[idx])};
        silkworm::ByteView hash_view{ethash_hash.bytes, silkworm::kHashLength};
        if (tx_hash == hash_view) {
            const auto block_header = block_with_hash.block.header;
            co_return TransactionWithBlock{block_with_hash, transactions[idx], block_with_hash.hash, block_header.number, block_header.base_fee_per_gas, idx};
        }
    }
    co_return std::nullopt;
}

} // namespace silkrpc::core
