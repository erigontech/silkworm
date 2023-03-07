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

#pragma once

#include <silkworm/silkrpc/config.hpp>

#include <boost/asio/awaitable.hpp>
#include <evmc/evmc.hpp>

#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkrpc::core  {

boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_number(BlockCache& cache, const rawdb::DatabaseReader& reader, uint64_t block_number);
boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& block_hash);
boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_number_or_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const silkrpc::BlockNumberOrHash& bnoh);
boost::asio::awaitable<silkworm::BlockWithHash> read_block_by_transaction_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& transaction_hash);
boost::asio::awaitable<std::optional<TransactionWithBlock>> read_transaction_by_hash(BlockCache& cache, const rawdb::DatabaseReader& reader, const evmc::bytes32& transaction_hash);

} // namespace silkrpc::core

