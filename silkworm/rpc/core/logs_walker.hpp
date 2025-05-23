// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/common/block_cache.hpp>
#include <silkworm/db/chain/providers.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/core/block_reader.hpp>
#include <silkworm/rpc/types/filter.hpp>
#include <silkworm/rpc/types/log.hpp>

namespace silkworm::rpc {

using boost::asio::awaitable;

class LogsWalker {
  public:
    LogsWalker(BlockCache& block_cache,
               db::kv::api::Transaction& tx,
               const db::chain::ChainStorage& chain_storage,
               WorkerPool& workers)
        : block_cache_(block_cache),
          tx_(tx),
          canonical_body_for_storage_provider_(db::chain::canonical_body_provider_from_chain_storage(chain_storage)),
          block_reader_(chain_storage, tx),
          workers_(workers) {}

    LogsWalker(const LogsWalker&) = delete;
    LogsWalker& operator=(const LogsWalker&) = delete;

    Task<std::pair<BlockNum, BlockNum>> get_block_nums(const Filter& filter);
    Task<void> get_logs(BlockNum start, BlockNum end,
                        const FilterAddresses& addresses, const FilterTopics& topics,
                        std::vector<Log>& logs) {
        LogFilterOptions options;
        co_return co_await get_logs(start, end, addresses, topics, options, /*ascending_order=*/true, logs);
    }
    Task<void> get_logs(BlockNum start, BlockNum end,
                        const FilterAddresses& addresses, const FilterTopics& topics,
                        const LogFilterOptions& options, bool ascending_order,
                        std::vector<Log>& logs);

  private:
    void filter_logs(const std::vector<Log>& logs,
                     const FilterAddresses& addresses,
                     const FilterTopics& topics,
                     std::vector<Log>& filtered_logs,
                     size_t max_logs);

    BlockCache& block_cache_;
    db::kv::api::Transaction& tx_;
    db::chain::CanonicalBodyForStorageProvider canonical_body_for_storage_provider_;
    BlockReader block_reader_;
    WorkerPool& workers_;
};

}  // namespace silkworm::rpc
